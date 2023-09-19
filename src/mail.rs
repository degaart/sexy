use anyhow::Result;
use lettre::{
    message::header::ContentType,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    Message, SmtpTransport, Transport,
};

pub fn send_mail(
    server: &str,
    port: u16,
    starttls: bool,
    login: &str,
    password: &str,
    from: &str,
    to: &[String],
    cc: &[String],
    bcc: &[String],
    subject: &str,
    body: &str,
) -> Result<()> {
    let mut message_builder = Message::builder()
        .header(ContentType::TEXT_PLAIN)
        .from(from.parse()?)
        .subject(subject.to_string());
    for recipient in to {
        message_builder = message_builder.to(recipient.parse()?);
    }

    for cc in cc {
        message_builder = message_builder.cc(cc.parse()?);
    }

    for bcc in bcc {
        message_builder = message_builder.bcc(bcc.parse()?);
    }

    let message = message_builder.body(body.to_string())?;

    let creds = Credentials::new(login.to_string(), password.to_string());
    let tls = TlsParameters::builder(server.to_string())
        .dangerous_accept_invalid_certs(true)
        .build()?;

    let smtp = SmtpTransport::builder_dangerous(server)
        .port(port.into())
        .tls(if starttls {
            Tls::Opportunistic(tls)
        } else {
            Tls::Wrapper(tls)
        })
        .credentials(creds)
        .build();
    smtp.send(&message)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::send_mail;
    use std::{
        collections::HashMap,
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    fn read_config(f: &Path) -> Result<HashMap<String, String>, std::io::Error> {
        let mut result = HashMap::new();
        let f = BufReader::new(File::open(f)?);
        for line in f.lines() {
            let line = line?;
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() == 2 {
                result.insert(tokens[0].to_lowercase(), tokens[1].to_string());
            }
        }
        Ok(result)
    }

    #[test]
    fn test_send_mail() {
        let config = read_config(Path::new("mail.cfg")).unwrap();
        let server = config.get("server").unwrap().as_str();
        let port = u16::from_str_radix(config.get("port").unwrap(), 10).unwrap();
        let starttls = match config.get("starttls").unwrap().as_str() {
            "true" | "yes" | "on" | "1" => true,
            "false" | "no" | "off" | "0" => false,
            _ => panic!("Invalid boolean value for starttls"),
        };
        let login = config.get("login").unwrap().as_str();
        let password = config.get("password").unwrap().as_str();
        let from = config.get("from").unwrap().as_str();
        let to = match config.get("to") {
            Some(to) => vec![to.clone()],
            None => panic!("Config did not include `to`"),
        };
        let cc = match config.get("cc") {
            Some(cc) => vec![cc.clone()],
            None => vec![],
        };
        let bcc = match config.get("bcc") {
            Some(bcc) => vec![bcc.clone()],
            None => vec![],
        };

        send_mail(
            server,
            port,
            starttls,
            login,
            password,
            from,
            &to,
            &cc,
            &bcc,
            "Test mail",
            "-= This is a test mail =-",
        )
        .unwrap();
    }
}
