use crate::config::UpstreamEndpoints;
use crate::filters::prelude::*;
use rlua::{Context, FromLua, Function, Lua as RLua, ToLua, UserData, UserDataMethods, Value};
use serde::{Deserialize, Serialize};
use slog::{warn, Logger};
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr as StdSocketAddr};
//use parking_lot::RwLock;
use std::sync::Mutex;

pub const NAME: &str = "quilkin.extensions.filters.lua.v1alpha1.Lua";

/// Creates a new factory for generating rhai filters.
pub fn factory(log: &Logger) -> DynFilterFactory {
    Box::from(LuaFactory { log: log.clone() })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    read_script: Option<String>,
    write_script: Option<String>,
}

struct LuaFactory {
    log: Logger,
}

impl FilterFactory for LuaFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct TODO;
        impl TryFrom<TODO> for Config {
            type Error = ConvertProtoConfigError;
            fn try_from(_: TODO) -> Result<Self, Self::Error> {
                unimplemented!()
            }
        }

        let filter = Lua::new(
            self.log.clone(),
            self.require_config(args.config)?
                .deserialize::<Config, TODO>(self.name())?,
        )
        .map_err(|err| Error::FieldInvalid {
            field: "script".into(),
            reason: format!("{:?}", err),
        })?;

        Ok(Box::new(filter))
    }
}

struct Lua {
    log: Logger,
    lua: std::sync::Mutex<RLua>,
    has_read_script: bool,
    has_write_script: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("failed to evaluate Lua {} script: {}", {script_type}, {error} )]
struct ScriptError {
    script_type: &'static str,
    error: rlua::Error,
}

impl ScriptError {
    fn read(error: rlua::Error) -> Self {
        Self {
            script_type: "read",
            error,
        }
    }
    fn write(error: rlua::Error) -> Self {
        Self {
            script_type: "write",
            error,
        }
    }
}

impl Lua {
    fn new(log: Logger, config: Config) -> Result<Lua, ScriptError> {
        let lua = RLua::new();

        if let Some(ref script) = config.read_script {
            let script = format!(
                "
{}
return read(ctx, contents, endpoints)
",
                script
            );
            lua.context(|ctx| {
                ctx.load(script.as_str())
                    .set_name(NAME)
                    .map_err(ScriptError::read)
                    .and_then(|chunk| chunk.into_function().map_err(ScriptError::read))
                    .and_then(|func| {
                        ctx.set_named_registry_value("read", func)
                            .map_err(ScriptError::read)
                    })
            })?
        }

        Ok(Lua {
            log,
            lua: Mutex::new(lua),
            has_read_script: config.read_script.is_some(),
            has_write_script: config.write_script.is_some(),
        })
    }
}

impl Filter for Lua {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        if !self.has_read_script {
            return Some(ctx.into());
        }

        let contents = Contents(std::mem::take(&mut ctx.contents));
        let endpoints = ctx
            .endpoints
            .iter()
            .map(|ep| SocketAddr(ep.address))
            .collect::<Vec<_>>();
        let lua = self.lua.lock().unwrap(); // TODO unwrap
        let response = lua.context(move |ctx| {
            let globals = ctx.globals();
            globals.set("contents", contents);
            globals.set("endpoints", endpoints);
            globals.set("ctx", PacketContext);

            ctx.named_registry_value::<_, Function>("read")
                .and_then(|func| {
                    func.call::<_, bool>(())
                })
                .map(|forward| {
                    if forward {
                        match globals.get::<_, Contents>("contents")
                            .and_then(|contents| globals.get::<_, Vec<SocketAddr>>("endpoints").map(|endpoints| (contents.0, endpoints))) {
                            Ok((contents, endpoints)) => {
                                Some((contents, endpoints))
                            },
                            Err(err) => {
                                warn!(self.log, "dropping packet that was requested to be forwarded from script"; "error" => %err);
                                None
                            }
                        }
                    } else {
                        None
                    }

                })
                .map_err(ScriptError::read)
        });

        match response {
            Ok(response) => {
                if let Some((contents, endpoints)) = response {
                    ctx.contents = contents;
                    // TODO retain scanning.
                    if ctx
                        .endpoints
                        .retain(|ep| endpoints.contains(&SocketAddr(ep.address)))
                        .is_none()
                    {
                        // TODO: Metrics
                        warn!(self.log, "Dropping packet due to script error"; "error" => "no endpoints were selected to forward packet to");
                        return None;
                    }
                    Some(ctx.into())
                } else {
                    // TODO: metrics
                    None
                }
            }
            Err(err) => {
                warn!(self.log, "dropping packet due to script evaluation error"; "error" => %err);
                None
            }
        }
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}

// Lua script types

#[derive(Debug, Clone)]
struct Contents(Vec<u8>);
impl<'lua> ToLua<'lua> for Contents {
    fn to_lua(self, lua: Context) -> rlua::Result<Value> {
        Ok(Value::String(lua.create_string(&self.0).unwrap()))
    }
}

// TODO is this needed.
impl<'lua> FromLua<'lua> for Contents {
    fn from_lua(value: Value<'lua>, lua: Context<'lua>) -> rlua::Result<Self> {
        match value {
            Value::String(contents) => Ok(Contents(Vec::from(contents.as_bytes()))),
            v => unreachable!("wtf {:?}", v),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct SocketAddr(StdSocketAddr);
impl UserData for SocketAddr {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("ip_string", |ctx, addr, ()| Ok(addr.0.ip().to_string()));
        methods.add_method("ip_bytes", |ctx, addr, ()| match addr.0 {
            StdSocketAddr::V4(addr) => Ok(Value::String(
                ctx.create_string(&addr.ip().octets()).unwrap(),
            )),
            StdSocketAddr::V6(addr) => Ok(Value::String(
                ctx.create_string(&addr.ip().octets()).unwrap(),
            )),
        });
        methods.add_method("port", |ctx, addr, ()| Ok(addr.0.port()));
    }
}

#[derive(Debug, Clone)]
struct PacketContext;
impl UserData for PacketContext {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("forward_packet", |ctx, pctx, ()| Ok(true));
        methods.add_method("drop_packet", |ctx, pctx, ()| Ok(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::Endpoint;
    use crate::config::Endpoints;
    use crate::test_utils::logger;

    fn test_read_context(
        contents: Vec<u8>,
        source: StdSocketAddr,
        endpoints: Vec<&'static str>,
    ) -> ReadContext {
        ReadContext::new(
            UpstreamEndpoints::from(
                Endpoints::new(
                    endpoints
                        .into_iter()
                        .map(|ep| Endpoint::from_address(ep.parse().unwrap()))
                        .collect(),
                )
                .unwrap(),
            ),
            source,
            contents,
        )
    }

    #[test]
    fn read_forward_packet() {
        let log = logger();
        let filter = Lua::new(
            log,
            Config {
                read_script: Some(
                    "
function read(ctx, contents, endpoints)
    print(type(contents))
    print(type(endpoints))
    print(type(ctx))
    return ctx:forward_packet()
end
"
                    .into(),
                ),
                write_script: None,
            },
        )
        .unwrap();
        let response = filter
            .read(test_read_context(
                Vec::from("hello".as_bytes()),
                "127.0.0.1:8080".parse().unwrap(),
                vec!["127.0.0.1:8081", "127.0.0.1:8082"],
            ))
            .unwrap();
        println!("{:?}", response.contents);
    }
}
