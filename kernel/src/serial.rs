//! Minimal 16550 UART driver on COM1, for early kernel debug output before
//! any real device model exists. QEMU's `-serial stdio` maps straight to
//! this port, which is what makes "did the kernel actually boot" verifiable
//! from the host instead of just trusting a black screen.

use core::fmt;
use core::fmt::Write;
use spin::Mutex;

const COM1: u16 = 0x3F8;

pub struct SerialPort;

impl SerialPort {
    /// # Safety
    /// Must only be called once, early in boot, before any other code
    /// touches COM1.
    pub unsafe fn init(&self) {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // enable DLAB (set baud rate divisor)
        outb(COM1, 0x03); // divisor low byte: 38400 baud
        outb(COM1 + 1, 0x00); // divisor high byte
        outb(COM1 + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(COM1 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }

    fn write_byte(&mut self, byte: u8) {
        unsafe {
            while (inb(COM1 + 5) & 0x20) == 0 {}
            outb(COM1, byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    value
}

pub static SERIAL1: Mutex<SerialPort> = Mutex::new(SerialPort);

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    SERIAL1
        .lock()
        .write_fmt(args)
        .expect("printing to serial port failed");
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(concat!($fmt, "\n"), $($arg)*));
}
