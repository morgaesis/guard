use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        if request.len() >= header_end + 4 + content_length {
            break;
        }
    }

    let arguments = r#"{\"name\":\"novel-diagnostic\",\"description\":\"Run the isolated novel diagnostic\",\"binary\":\"novelctl\",\"args\":[\"status\"],\"params\":{},\"consequence\":\"reversible\",\"trusted\":false,\"evidence\":\"The fixture returns static diagnostic state.\"}"#;
    let body = format!(
        r#"{{"choices":[{{"message":{{"tool_calls":[{{"id":"fixture","type":"function","function":{{"name":"create_verb","arguments":"{arguments}"}}}}]}}}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
    );
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:38473")?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| {
                    let _ = serve(stream);
                });
            }
            Err(error) => eprintln!("fake evaluator accept failed: {error}"),
        }
    }
    Ok(())
}
