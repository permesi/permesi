use anyhow::Result;

fn main() -> Result<()> {
    let doc = genesis::api::openapi();
    let json = serde_json::to_string_pretty(&doc)?;
    println!("{json}");
    Ok(())
}
