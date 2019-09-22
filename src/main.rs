extern crate cgi;
extern crate serde;
extern crate serde_json;
extern crate jsonwebtoken;
extern crate base64;

use std::fs;
use std::str;
use std::env;
use std::io::Write;
use std::process; use std::process::Stdio;
use std::time::SystemTime;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use openssl::rsa;

const DEBUG: bool = true;

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
    output: String,
}

fn get_key(group: &str, user: &str, is_private: bool) -> Result<(String, Vec<u8>), String> {
    match fs::read_to_string(format!("config/keys/{}/{}", group, user)) {
        Ok(s) => {
            if is_private {
                let key = match rsa::Rsa::private_key_from_pem(s.as_bytes()) {
                    Ok(k) => k,
                    Err(_) => return Err("Could Not Decode Private Key!".to_owned())
                };
                let pem = match key.private_key_to_pem() {
                    Ok(k) => match str::from_utf8(&k[..]) {
                        Ok(s) => s.to_owned(),
                        Err(_) => return Err(format!("Could Not Convert Key to string!"))
                    }
                    Err(e) => return Err(format!("Could Not Convert Key to PEM! {}", e))
                };
                let der = match key.private_key_to_der() {
                    Ok(k) => k,
                    Err(e) => return Err(format!("Could Not Convert Key to DER! {}", e))
                };
                Ok((pem.to_owned(), der))
            } else {
                let key = match rsa::Rsa::public_key_from_pem(s.as_bytes()) {
                    Ok(k) => k,
                    Err(_) => return Err("Could Not Decode Private Key!".to_owned())
                };
                let pem = match key.public_key_to_pem() {
                    Ok(k) => match str::from_utf8(&k[..]) {
                        Ok(k) => k.to_owned(),
                        Err(_) => return Err(format!("Could Not Convert Key to string!"))
                    }
                    Err(e) => return Err(format!("Could Not Convert Key to PEM! {}", e))
                };
                let der = match key.public_key_to_der() {
                    Ok(k) => k,
                    Err(e) => return Err(format!("Could Not Convert Key to DER! {}", e))
                };
                let mut f = fs::File::create("/tmp/pemkey").unwrap();
                f.write_all(pem.as_bytes()).unwrap();
                Ok((pem.to_owned(), der))
            }
        }
        Err(_) => Err("Key Not Found!".to_owned())
    }
}

fn error_to_htmlerror(e: impl std::fmt::Display, code: u16, text: &str) -> HTMLError {
    if DEBUG {
        return HTMLError {
            error: format!("{}; {}", text, e),
            status_code: code
        };
    }
    return HTMLError {
        error: "Permission Denied.".to_owned(),
        status_code: code
    }

}

fn get_env_vars_from_request<'a>(request: &RequestJWT) -> HashMap<&'a str, String>{
    [
        ("OPERATOR_GROUP", request.group.to_string()),
        ("OPERATOR_USER", request.user.to_string()),
        ("OPERATOR_IAT", request.iat.to_string())
    ].iter().cloned().collect()

}

fn run_external_command<'a>(operation_path: &str, input: &str, environment: HashMap<&str, String>) -> Result<String, String> {
    let mut operation_cmd = match process::Command::new(operation_path)
                                                    .stdin(Stdio::piped())
                                                    .stdout(Stdio::piped())
                                                    .envs(&environment)
                                                    .spawn() {
        Ok(cmd) => cmd,
        Err(e) => return Err(format!("Error Running Command: {}", e))
    };

    match operation_cmd.stdin.as_mut() {
        Some(cmd) => cmd.write_all(input.as_bytes()).unwrap(),
        None => return Err("Could Not Open".to_string())
    }

    return match operation_cmd.wait_with_output() {
        Ok(output) => Ok(
            str::from_utf8(&output.stdout[..]).unwrap().to_string()
        ),
        Err(e) => Err(e.to_string())
    };

}

fn process_request(
    request_string: &str,
) -> Result<ResponseJWT, HTMLError> {

    let unsafe_request = match jsonwebtoken::dangerous_unsafe_decode::<RequestJWT>(
        &request_string
    ) {
        Ok(token) => token,
        Err(e) => return Err(error_to_htmlerror(e, 400, "Invalid Token"))
    };
    let group = unsafe_request.claims.group;
    let operation = unsafe_request.claims.operation;
    let user = unsafe_request.claims.user;

    // let (_, user_key) = get_key(&group, &user, false).unwrap();
    let user_key = match fs::read(
        format!("config/keys/{}/{}", group, user)
    ) {
        Ok(key) => key,
        Err(e) => return Err(error_to_htmlerror(e, 403, "Permission Denied"))
    };
    

    let request: RequestJWT = match jsonwebtoken::decode::<RequestJWT>(
        &request_string,
        &user_key[..],
        &jsonwebtoken::Validation::new(
            jsonwebtoken::Algorithm::RS256
        )
    ){
        Ok(r) => r.claims,
        Err(e) => return Err(error_to_htmlerror(e, 403, "Permission Denied"))
    };
    
    let operation_path = format!("{}/config/operations/{}/{}", env::current_dir().unwrap().display(), group, operation);

    match fs::metadata(&operation_path) {
        Ok(m) => if m.is_file() {()} else {
            return Err(error_to_htmlerror("Not a File", 404, "Operation Not Found"))
        },
        Err(e) => return Err(error_to_htmlerror(e, 404, "Operation Not Found"))
    };
    
    let iat_time = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("Invalid Time"),
    };

    let command_result = match run_external_command(
        &operation_path,
        &request.input[..],
        get_env_vars_from_request(&request),
    ){
        Ok(result) => result,
        Err(e) => return Err(error_to_htmlerror(e, 500, "Command Failed"))
    };

    return Ok(ResponseJWT {
        iat: iat_time,
        group: group,
        operation: operation,
        output: command_result.to_owned()
    });

}

fn err_response(error: HTMLError) -> cgi::Response {
    cgi::html_response(
        error.status_code,
        serde_json::to_string(&error).unwrap()
    )
}

fn cgi_post_operation(body: Vec<u8>) -> cgi::Response {
    let (_, private_key) = match get_key("operator", "private.pem", true) {
        Ok(private_key) => private_key,
        Err(e) => return err_response(error_to_htmlerror(e, 500, "Server Keys not Accessible"))
    };

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

fn cgi_get_public_key() -> cgi::Response {
    let (public_key_text, _) = match get_key("operator", "public.pem", false) {
        Ok(public_key) => public_key,
        Err(e) => return err_response(error_to_htmlerror(e, 500, "Server Keys not Accessible"))
    };
    return cgi::html_response(
        200,
        public_key_text
    )
}

fn cgi_handler(request: cgi::Request, path: &str) -> cgi::Response {
    let (parts, body) = request.into_parts();
    if path.starts_with("/operation") {
        if parts.method != cgi::http::Method::POST {
            return err_response(HTMLError {
                error: "Method Unsupported".to_owned(),
                status_code: 405,
            })
        }
        return cgi_post_operation(body);
    }
    else if path == "/public_key" {
        if parts.method != cgi::http::Method::GET {
            return err_response(HTMLError {
                error: "Method Unsupported".to_owned(),
                status_code: 405,
            })
        }
        return cgi_get_public_key();
    }
    
    err_response(HTMLError {
        error: "Page Not Found.".to_owned(),
        status_code: 404
    })

}

fn cgi_handler_wrapper(request: cgi::Request) -> cgi::Response {
    let mut path = std::env::var("PATH_INFO").unwrap();
    if path.ends_with('/'){
        path.pop();
    }

    cgi_handler(request, &path)
}

fn main() {
    cgi::handle(cgi_handler_wrapper)
}
