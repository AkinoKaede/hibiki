#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hibiki::frontend::run(hibiki_lib::protocol::ServiceKind::Scdaemon).await
}
