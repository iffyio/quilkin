use crate::config::UpstreamEndpoints;
use crate::filters::prelude::*;
use rhai::{Dynamic, Engine, ParseError, Scope, AST};
use serde::{Deserialize, Serialize};
use slog::{warn, Logger};
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr as StdSocketAddr};

pub const NAME: &str = "quilkin.extensions.filters.rhai.v1alpha1.Rhai";

/// Creates a new factory for generating rhai filters.
pub fn factory(log: &Logger) -> DynFilterFactory {
    Box::from(RhaiFactory { log: log.clone() })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    read_script: Option<String>,
    write_script: Option<String>,
}

struct RhaiFactory {
    log: Logger,
}

impl FilterFactory for RhaiFactory {
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

        let filter = Rhai::new(
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

struct Rhai {
    log: Logger,
    engine: Engine,
    read_ast: Option<AST>,
    write_ast: Option<AST>,
}

#[derive(Debug, PartialEq, thiserror::Error)]
#[error("failed to compile script: {}", .0)]
struct ScriptCompilationError(ParseError);

impl Rhai {
    fn new(log: Logger, config: Config) -> Result<Rhai, ScriptCompilationError> {
        println!("{}", config.read_script.clone().unwrap());
        let mut engine = Engine::new();

        engine
            .register_type::<SocketAddr>()
            .register_fn("ip_string", SocketAddr::ip_string)
            .register_fn("ip_bytes", SocketAddr::ip_bytes)
            .register_fn("ip_port", SocketAddr::port);

        engine
            .register_type::<PacketResponse>()
            .register_fn("forward_packet", PacketResponse::forward)
            .register_fn("drop_packet", PacketResponse::drop);

        fn compile_script(
            engine: &Engine,
            script: Option<String>,
        ) -> Result<Option<AST>, ScriptCompilationError> {
            script
                .map(|script| {
                    engine
                        .compile(script.as_str())
                        .map_err(ScriptCompilationError)
                })
                .transpose()
        }

        let read_ast = compile_script(&engine, config.read_script)?;
        let write_ast = compile_script(&engine, config.write_script)?;
        Ok(Rhai {
            log,
            engine,
            read_ast,
            write_ast,
        })
    }
}

impl Filter for Rhai {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        if let Some(ast) = &self.read_ast {
            let mut scope = Scope::new();

            let contents = std::mem::take(&mut ctx.contents);
            let eval_result: Result<Result<PacketResponse, String>, _> = self.engine.call_fn(
                &mut scope,
                ast,
                "read",
                ScriptReadArgs::new(contents, &ctx.endpoints),
            );

            let script_result = match eval_result {
                Ok(result) => result,
                Err(err) => {
                    warn!(self.log, "Dropping packet due to script evaluation error"; "error" => %err);
                    return None;
                }
            };

            match script_result {
                Ok(response) => {
                    match response {
                        PacketResponse::Drop => {
                            // TODO: Metrics
                            return None;
                        }
                        PacketResponse::Forward {
                            contents: content,
                            endpoints,
                        } => {
                            if ctx
                                .endpoints
                                .retain(|ep| endpoints.contains(&SocketAddr::from(ep.address)))
                                .is_none()
                            {
                                // TODO: Metrics
                                warn!(self.log, "Dropping packet due to script error"; "error" => "No endpoints were selected to forward packet to");
                                return None;
                            }
                            ctx.contents = content
                        }
                    }
                }
                Err(err) => {
                    warn!(self.log, "Dropping packet due to script error"; "error" => %err)
                }
            }
        }

        Some(ctx.into())
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}

// Rhai script types

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct SocketAddr {
    inner: StdSocketAddr,
}
impl From<StdSocketAddr> for SocketAddr {
    fn from(address: StdSocketAddr) -> Self {
        SocketAddr { inner: address }
    }
}

impl SocketAddr {
    pub fn ip_string(&mut self) -> String {
        self.inner.ip().to_string()
    }

    pub fn ip_bytes(&mut self) -> rhai::Array {
        match self.inner.ip() {
            IpAddr::V4(ip) => {
                let ip_bytes = ip.octets();
                ip_bytes
                    .iter()
                    .cloned()
                    .map(|byte| rhai::Dynamic::from(byte))
                    .collect()
            }
            IpAddr::V6(ip) => {
                let ip_bytes = ip.octets();
                ip_bytes
                    .iter()
                    .cloned()
                    .map(|byte| rhai::Dynamic::from(byte))
                    .collect()
            }
        }
    }

    fn port(&mut self) -> u16 {
        self.inner.port()
    }
}

#[derive(Debug, Clone)]
pub enum PacketResponse {
    Forward {
        contents: Vec<u8>, // TODO: contents
        endpoints: Vec<SocketAddr>,
    },
    Drop,
}

fn convert_rhai_array<T: 'static>(
    array: rhai::Array,
    type_name: &'static str,
) -> Result<Vec<T>, String> {
    array
        .into_iter()
        .enumerate()
        .map(|(i, value)|{
            let value_type_name = value.type_name();
            value.try_cast::<T>().ok_or_else(|| format!("invalid value: at index {}: the value has an unexpected type `{}` expected type `{}`", i, value_type_name, type_name))
        }).collect::<Result<Vec<_>, _>>()
}

impl PacketResponse {
    fn forward(content: rhai::Array, endpoints: rhai::Array) -> Result<PacketResponse, String> {
        if endpoints.is_empty() {
            return Err("no endpoints were provided in call to `forward_packet`".into());
        }

        Ok(PacketResponse::Forward {
            contents: convert_rhai_array(content, "Vec<u8>")?,
            endpoints: convert_rhai_array(endpoints, "Vec<SocketAddress>")?,
        })
    }
    fn drop() -> Result<PacketResponse, String> {
        Ok(PacketResponse::Drop)
    }
}

struct ScriptReadArgs {
    pub contents: rhai::Array,
    pub endpoints: rhai::Array,
}

impl ScriptReadArgs {
    fn new(contents: Vec<u8>, endpoints: &UpstreamEndpoints) -> ScriptReadArgs {
        ScriptReadArgs {
            contents: contents
                .into_iter()
                .map(|byte| rhai::Dynamic::from(byte))
                .collect(),
            endpoints: endpoints
                .iter()
                .map(|ep| rhai::Dynamic::from(SocketAddr::from(ep.address)))
                .collect(),
        }
    }
}

impl rhai::FuncArgs for ScriptReadArgs {
    fn parse<CONTAINER: Extend<Dynamic>>(self, container: &mut CONTAINER) {
        container.extend(std::iter::once(rhai::Dynamic::from(self.contents)));
        container.extend(std::iter::once(rhai::Dynamic::from(self.endpoints)));
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
        let filter = Rhai::new(
            log,
            Config {
                read_script: Some(
                    "
fn read(contents, endpoints) {
print(type_of(contents));
print(type_of(endpoints));
forward_packet(contents, endpoints);
}
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
