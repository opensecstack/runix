//! PL011 UART driver, polling/register-banged -- no interrupt-driven I/O
//! yet (there's no exception vector table wired up to receive one). Base
//! address is QEMU `virt`'s fixed, documented UART0 location, not
//! board-specific guesswork; a real device tree walk to discover it is
//! later work, once this boots on something other than QEMU.

const UART0_BASE: usize = 0x0900_0000;
const UART_DR: *mut u8 = UART0_BASE as *mut u8;

/// Writes one byte to the UART's data register.
///
/// # Safety
/// `UART0_BASE` must be mapped and be a real PL011 UART -- true for QEMU's
/// `virt` machine by construction, not yet verified against any other
/// target.
pub fn write_byte(byte: u8) {
    unsafe {
        core::ptr::write_volatile(UART_DR, byte);
    }
}

pub fn write_str(s: &str) {
    for byte in s.bytes() {
        write_byte(byte);
    }
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => {
        $crate::serial_print!("{}\n", format_args!($($arg)*))
    };
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct Writer;
    impl Write for Writer {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            write_str(s);
            Ok(())
        }
    }
    let _ = Writer.write_fmt(args);
}
