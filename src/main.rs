extern crate cgi;
extern crate serde;
extern crate serde_json;
extern crate jsonwebtoken;
extern crate base64;

use std::fs;
use std::str;
use std::io::Write;
use std::process;
use std::process::Stdio;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
struct HTMLError {
    error: String,
    status_code: u16,
}

#[derive(Serialize, Deserialize)]
struct RequestJWT {
    iat: u64,
    group: String,
    user: String,
    operation: String,
    input: String,
}

#[derive(Serialize, Deserialize)]
struct ResponseJWT {
    iat: u64,
    group: String,
    operation: String,
    input: String,
    output: String,
}

fn process_request(
    request_string: &str,
) -> Result<ResponseJWT, HTMLError> {
    let debug = false;
    let unsafe_request = match jsonwebtoken::dangerous_unsafe_decode::<RequestJWT>(
        &request_string
    ) {
        Ok(token) => token,
        Err(_) => return Err(HTMLError {
            error: "Invalid Token".to_owned(),
            status_code: 400
        })
    };
    let group = unsafe_request.claims.group;
    let operation = unsafe_request.claims.operation;
    let user = unsafe_request.claims.user;

    let user_key = match fs::read(
        format!("config/keys/{}/{}", group, user)
    ) {
        // Ok(key) => pem_parser::pem_to_der(&key),
        Ok(key) => key,
        Err(e) => {
            if debug {
                return Err(HTMLError {
                    status_code: 403,
                    error: format!("Permission Denied; {}", e)
                });
            }
            return Err(HTMLError {
                error: "Permission Denied.".to_owned(),
                status_code: 403
            })
        }
    };

    let request: RequestJWT = match jsonwebtoken::decode::<RequestJWT>(
        &request_string,
        &user_key[..],
        //user_key,
        &jsonwebtoken::Validation::new(
            jsonwebtoken::Algorithm::RS256
        )
    ){
        Ok(r) => r.claims,
        Err(e) => {
            if debug {
                return Err(HTMLError {
                    status_code: 403,
                    error: format!("Permission Denied; {}", e)
                });
            }
            return Err(HTMLError {
                error: "Permission Denied.".to_owned(),
                status_code: 403
            })
        }
    };
    
    let operation_path = format!("config/operation/{}/{}", group, operation);
    

    match fs::metadata(&operation_path) {
        Ok(_) => (),
        Err(_) => {
            return Err(HTMLError {
                error: "Operation Not Found.".to_owned(),
                status_code: 404
            })
        }
    };

    let mut operation_cmd = process::Command::new(&operation_path)
                                          .stdin(Stdio::piped())
                                          .stdout(Stdio::piped())
                                          .spawn()
                                          .unwrap();
    operation_cmd.stdin
        .as_mut()
        .ok_or(HTMLError {
            error: "Child Process Not Opened!".to_owned(),
            status_code: 500
        })?
        .write_all(request.input.as_bytes()).unwrap();

    let operation_output = match operation_cmd.wait_with_output() {
        Ok(output) => output,
        Err(_) => return Err(HTMLError {
            error: "Operation Failed".to_owned(),
            status_code: 500
        })
    };
    
    let iat_time = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("Invalid Time"),
    };

    return Ok(ResponseJWT {
        iat: iat_time,
        group: request.group,
        operation: request.operation,
        input: request.input,
        output: str::from_utf8(&operation_output.stdout[..]).unwrap().to_owned(),
    });

}

fn err_response(error: HTMLError) -> cgi::Response {
    cgi::html_response(
        error.status_code,
        serde_json::to_string(&error).unwrap()
    )
}

fn get_key(group: &str, user: &str) -> Result<(String, Vec<u8>), ()> {
    match fs::read_to_string(format!("config/keys/{}/{}", group, user)) {
        Ok(s) => {
            let der = pem_parser::pem_to_der(&s);
            Ok((s, der))
        }
        Err(_) => Err(())
    }
}

fn cgi_handler(request: cgi::Request) -> cgi::Response {
    let (public_key_text, _) = match get_key("operator", "public.pem") {
        Ok(public_key) => public_key,
        Err(()) => return err_response(HTMLError {
            error: "Server Keys Not Accessible.".to_owned(),
            status_code: 500
        })
    };
    let (_, private_key) = match get_key("operator", "private.pem") {
        Ok(public_key) => public_key,
        Err(()) => return err_response(HTMLError {
            error: "Server Keys Not Accessible.".to_owned(),
            status_code: 500
        })
    };

    let mut path = std::env::var("PATH_INFO").unwrap();
    if path.ends_with('/'){
        path.pop();
    }

    if path.starts_with("/operation") {
        let (parts, body) = request.into_parts();
        if parts.method != cgi::http::Method::POST {
            return err_response(HTMLError {
                error: "Method Unsupported".to_owned(),
                status_code: 405,
            })
        }
        return match process_request(str::from_utf8(&body[..]).unwrap()) {
            Ok(jwt) => cgi::html_response(
                200,
                jsonwebtoken::encode(
                    &jsonwebtoken::Header::new(
                        jsonwebtoken::Algorithm::RS256
                    ),
                    &jwt,
                    &private_key[..]
                ).unwrap()
            ),
            Err(e) => err_response(e)
        };

    }
    else if path == "/public_key" {
        return cgi::html_response(
            200,
            public_key_text.to_owned()
        )
    }
    
    err_response(HTMLError {
        error: "Page Not Found.".to_owned(),
        status_code: 404
    })
}

fn main() {
    cgi::handle(cgi_handler)
}
