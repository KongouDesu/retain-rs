use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use std::io::Write;

/// Prints the given text with the given color
/// Does not include a newline
pub fn printcol<T: AsRef<str>>(color: Color, text: T) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(color))).unwrap();
    write!(&mut stdout, "{}", text.as_ref()).unwrap();
    stdout.reset().unwrap();
    stdout.flush();
}

/// Prints the given text with the given color
/// Include a newline
pub fn printcoln<T: AsRef<str>>(color: Color, text: T) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(color))).unwrap();
    writeln!(&mut stdout, "{}", text.as_ref()).unwrap();
    stdout.reset().unwrap();
    stdout.flush();
}