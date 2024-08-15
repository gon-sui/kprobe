#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    helpers::bpf_probe_read_kernel,
};
use aya_log_ebpf::info;

#[repr(C)]
pub struct sock {
    __sk_common: sock_common,
    // その他のフィールド
}

#[repr(C)]
pub struct sock_common {
    skc_family: u16,
    skc_state: u8,
    skc_reuse: u8,
    skc_reuseport: u8,
    skc_ipv6only: u8,
    skc_net: u32,
    __bindgen_anon_1: __bindgen_anon_1,
    __bindgen_anon_2: __bindgen_anon_2,
    __bindgen_anon_3: __bindgen_anon_3,
    skc_hash: u32,
    skc_u16hashes: u32,
}

#[repr(C)]
pub struct __bindgen_anon_1 {
    skc_daddr: u32,
    skc_rcv_saddr: u32,
}

#[repr(C)]
pub struct __bindgen_anon_2 {
    skc_dport: u16,
    skc_num: u16,
}

#[repr(C)]
pub struct __bindgen_anon_3 {
    skc_cookie: u32,
}

const AF_INET: u16 = 2;

#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match unsafe { try_kprobetcp(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, u32> {
    let sock: *const sock = ctx.arg(0).ok_or(1u32)?;
    let sk_common: sock_common = bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
        .map_err(|_| 2u32)?;

    if sk_common.skc_family != AF_INET {
        return Ok(0);
    }

    let src_addr = sk_common.__bindgen_anon_1.skc_rcv_saddr;
    let dest_addr = sk_common.__bindgen_anon_1.skc_daddr;
    let dest_port = u16::from_be(sk_common.__bindgen_anon_2.skc_dport);

    info!(
        &ctx,
        "AF_INET src address: {:i}, dest address: {:i}, dest port: {}",
        src_addr,
        dest_addr,
        dest_port,
    );

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
