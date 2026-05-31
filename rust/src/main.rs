use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tonic::{Request, Response, Status};
use tracing_subscriber::EnvFilter;

mod frame;
mod scanner;

use scanner::payload::PayloadScanner;

pub mod fortress_scanner_v1 {
    tonic::include_proto!("fortress.scanner.v1");
}

use fortress_scanner_v1::scanner_service_server::{ScannerService, ScannerServiceServer};
use fortress_scanner_v1::{ScanRequest, ScanResponse};

#[derive(Debug)]
struct ScannerServiceImpl {
    scanner: Arc<PayloadScanner>,
}

#[tonic::async_trait]
impl ScannerService for ScannerServiceImpl {
    async fn scan_frame(
        &self,
        request: Request<ScanRequest>,
    ) -> Result<Response<ScanResponse>, Status> {
        let req = request.into_inner();
        let result = self.scanner.scan(&req.payload);
        let reply = ScanResponse {
            is_threat: result.is_threat,
            threat_type: result.threat_type,
            confidence: result.confidence,
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let addr: SocketAddr = env::var("SCANNER_GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()
        .expect("invalid SCANNER_GRPC_ADDR");

    let scanner = Arc::new(PayloadScanner::new());
    let svc = ScannerServiceServer::new(ScannerServiceImpl { scanner });

    tracing::info!(addr = %addr, "starting gRPC scanner server");

    tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, async {
            signal::ctrl_c().await.ok();
            tracing::info!("received shutdown signal, stopping gracefully");
        })
        .await?;

    Ok(())
}
