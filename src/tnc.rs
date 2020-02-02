use std::str::FromStr;

#[derive(PartialEq, Debug)]
pub struct TcpKissConfig {
    // Use a String to accept domain names. Even for IP addresses we will typically
    // receive this in a textual format from a parameter or config file.
    host: String,
    port: u16,
}

#[derive(PartialEq, Debug)]
pub struct LinuxIfConfig {
    ifname: String, // e.g. "ax0"
}

#[derive(PartialEq, Debug)]
enum ConnectConfig {
    TcpKiss(TcpKissConfig),
    LinuxIf(LinuxIfConfig),
}

#[derive(PartialEq, Debug)]
pub struct TncAddress {
    config: ConnectConfig,
}

impl TncAddress {
    /// Programmatically create a `TncAddress` pointing to a Linux network interface.
    pub fn new_linuxif(linuxif: LinuxIfConfig) -> Self {
        TncAddress {
            config: ConnectConfig::LinuxIf(linuxif),
        }
    }

    /// Porgrammatically create a `TncAddress` pointing to a KISS TCP service.
    pub fn new_tcpkiss(tcpkiss: TcpKissConfig) -> Self {
        TncAddress {
            config: ConnectConfig::TcpKiss(tcpkiss),
        }
    }
}

impl FromStr for TncAddress {
    type Err = (); // TODO errors that are useful to the end user

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = s.split(':').collect();
        if components.len() < 2 {
            return Err(());
        }
        if components[0] != "tnc" {
            return Err(());
        }
        Ok(match components[1] {
            "tcpkiss" => {
                if components.len() != 4 {
                    return Err(());
                }
                TncAddress {
                    config: ConnectConfig::TcpKiss(TcpKissConfig {
                        host: components[2].to_string(),
                        port: match components[3].parse() {
                            Ok(port) => port,
                            _ => return Err(()),
                        },
                    }),
                }
            }
            "linuxif" => {
                if components.len() != 3 {
                    return Err(());
                }
                TncAddress {
                    config: ConnectConfig::LinuxIf(LinuxIfConfig {
                        ifname: components[2].to_string(),
                    }),
                }
            }
            _ => {
                return Err(());
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_tnc_addresses() {
        assert_eq!(
            "tnc:tcpkiss:192.168.0.1:8001".parse::<TncAddress>(),
            Ok(TncAddress {
                config: ConnectConfig::TcpKiss(TcpKissConfig {
                    host: "192.168.0.1".to_string(),
                    port: 8001_u16,
                })
            })
        );
        assert_eq!(
            "tnc:linuxif:ax0".parse::<TncAddress>(),
            Ok(TncAddress {
                config: ConnectConfig::LinuxIf(LinuxIfConfig {
                    ifname: "ax0".to_string(),
                })
            })
        );
        assert_eq!("fish".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss:".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss:a:b:c".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss:192.168.0.1".parse::<TncAddress>(), Err(()));
        assert_eq!(
            "tnc:tcpkiss:192.168.0.1:hello".parse::<TncAddress>(),
            Err(())
        );
    }
}
