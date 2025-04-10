use std::{env::current_exe, str::FromStr};

use anyhow::{Result, bail};
use pico_args::Arguments;

use crate::{config, config_path};

pub fn run_cli() -> Result<()> {
    let mut args = Arguments::from_env();
    let print: Option<Info> = args.opt_value_from_str("--print")?;
    if let Some(print) = print {
        match print {
            Info::ConfigPath => println!("{}", super::config_path().display()),
            Info::ActiveModule => println!("{}", super::config()?.pkcs11_module_path.display()),
        }
    } else {
        println!("An IC auth plugin for PKCS#11 hardware keys.");
        if config().is_err() {
            println!(
                "\nMust be configured before first use. Edit {}.",
                config_path().display()
            );
        }
        let self_path = current_exe().unwrap();
        let self_name = self_path.file_name().unwrap();
        println!(
            "\nPlugins do not need to be run directly. To use the plugin with an app that supports plugins, \
            go to the app's plugin settings and enter the path {}",
            self_path.display()
        );
        println!(
            "
{0} --print config-path
    Displays the path to the configuration.
{0} --print active-module
    Displays the PKCS#11 module currently configured.",
            self_name.to_string_lossy()
        );
    }
    Ok(())
}

#[derive(Debug, Copy, Clone)]
enum Info {
    ConfigPath,
    ActiveModule,
}

impl FromStr for Info {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "config-path" => Ok(Self::ConfigPath),
            "active-module" => Ok(Self::ActiveModule),
            s => bail!("unknown print option {s}"),
        }
    }
}
