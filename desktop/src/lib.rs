//! Desktop-specific layers: shell, grid sandbox, filesystem/network drivers.
//! Mostly an empty placeholder — first real work lands in Beta (grid
//! sandbox isolation, user-space network stack, filesystem driver) — except
//! [`citadel`], the desktop-side CITADEL/MARSHAL user-space proxy transport.

pub mod citadel;
