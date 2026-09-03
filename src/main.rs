#[actix_web::main]
async fn main() -> std::io::Result<()> {
    iptv_rs::run().await
}
