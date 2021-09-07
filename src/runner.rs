/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::Arc;

use slog::{info, o};
use tokio::{signal, sync::watch};

use crate::{
    config::Config,
    filters::{DynFilterFactory, FilterRegistry, FilterSet},
    proxy::Builder,
};

#[cfg(doc)]
use crate::filters::FilterFactory;

pub type Error = Box<dyn std::error::Error>;

/// Calls [`run`] with the [`Config`] found by [`Config::find`] and the
/// default [`FilterSet`].
pub async fn run(
    filter_factories: impl IntoIterator<Item = DynFilterFactory>,
) -> Result<(), Error> {
    let log = crate::proxy::logger();
    run_with_config(
        log.clone(),
        Config::find(&log, None).map(Arc::new)?,
        filter_factories,
    )
    .await
}

/// Start and run a proxy. Any passed in [`FilterFactory`]s are included
/// alongside the default filter factories.
pub async fn run_with_config(
    base_log: slog::Logger,
    config: Arc<Config>,
    filter_factories: impl IntoIterator<Item = DynFilterFactory>,
) -> Result<(), Error> {
    let log = base_log.new(o!("source" => "run"));
    let server = Builder::from(config)
        .with_log(base_log)
        .with_filter_registry(FilterRegistry::new(FilterSet::default_with(
            &log,
            filter_factories.into_iter(),
        )))
        .validate()?
        .build();

    let mut sig_term = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
    let signal_log = log.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!(signal_log, "Received SIGINT")
            }
            _ = sig_term.recv()=> {
                info!(signal_log, "Received SIGTERM")
            }
        }
        // Don't unwrap in order to ensure that we execute
        // any subsequent shutdown tasks.
        shutdown_tx.send(()).ok();
    });

    if let Err(err) = server.run(shutdown_rx).await {
        info!(log, "Shutting down with error"; "error" => %err);
        Err(Error::from(err))
    } else {
        info!(log, "Shutting down");
        Ok(())
    }
}
