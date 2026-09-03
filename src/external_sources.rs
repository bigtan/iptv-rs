use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use log::warn;
use reqwest::Client;
use std::io::Cursor;
use tokio::task::JoinSet;
use xml::EventReader;

pub(crate) const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const FETCH_MAX_BYTES: usize = 8 * 1024 * 1024;

pub(crate) async fn fetch_text(client: &Client, url: &str) -> Result<String> {
    let url = reqwest::Url::parse(url)?;
    let response = client.get(url).send().await?.error_for_status()?;
    if let Some(len) = response.content_length()
        && len > FETCH_MAX_BYTES as u64
    {
        return Err(anyhow!("Response too large"));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(FETCH_MAX_BYTES as u64) as usize,
    );
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        append_limited(&mut body, &chunk, FETCH_MAX_BYTES)?;
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn append_limited(body: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<()> {
    let new_len = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| anyhow!("Response too large"))?;
    if new_len > limit {
        return Err(anyhow!("Response too large"));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

pub(crate) async fn parse_xml(client: &Client, url: &str) -> Result<EventReader<Cursor<String>>> {
    Ok(EventReader::new(Cursor::new(
        fetch_text(client, url).await?,
    )))
}

async fn parse_playlist(client: &Client, url: &str) -> Result<String> {
    let response = fetch_text(client, url).await?;
    if response.starts_with("#EXTM3U") {
        response
            .find('\n')
            .map(|i| response[i..].to_owned())
            .ok_or(anyhow!("Empty playlist"))
    } else {
        Err(anyhow!("Playlist does not start with #EXTM3U"))
    }
}

pub(crate) async fn fetch_playlists(client: &Client, urls: &[String]) -> Vec<(usize, String)> {
    let mut set = JoinSet::new();
    for (index, url) in urls.iter().cloned().enumerate() {
        let client = client.clone();
        set.spawn(async move {
            let result = parse_playlist(&client, &url).await;
            (index, url, result)
        });
    }
    let mut playlists = Vec::new();
    while let Some(result) = set.join_next().await {
        match result {
            Ok((index, _, Ok(content))) => playlists.push((index, content)),
            Ok((_, url, Err(error))) => warn!("Failed to parse extra playlist ({url}): {error}"),
            Err(error) => warn!("Task join error parsing extra playlist: {error}"),
        }
    }
    playlists.sort_by_key(|(index, _)| *index);
    playlists
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_limit_rejects_the_chunk_that_crosses_the_boundary() {
        let mut body = vec![0; 4];
        append_limited(&mut body, &[1, 2, 3, 4], 8).unwrap();
        assert!(append_limited(&mut body, &[5], 8).is_err());
        assert_eq!(body.len(), 8);
    }
}
