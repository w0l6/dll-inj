extern crate winapi;

use eframe::*;
use eframe::{NativeOptions, App};
use std::ffi::CString;
use std::ptr;
use winapi::um::winnt::HANDLE;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winbase::*;
use winapi::um::synchapi::*;
use winapi::um::handleapi::*;
use winapi::um::winnt::*;
use winapi::shared::minwindef::{FALSE, LPVOID, DWORD, HMODULE};
use winapi::um::psapi::{EnumProcesses, EnumProcessModules, GetModuleBaseNameA, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use rfd::FileDialog;
use std::io::Write;
use winapi::um::winbase::INFINITE;
use std::ptr::null_mut;

#[derive(Clone)]
struct Process {
    pid: DWORD,
    name: String,
    byte: f64,
}

struct MyApp {
    name: String,
    age: i32,
    selected_process: Option<Process>,
    ui_state: UIState,
    processes: Vec<Process>,
    search_query: String,  
    dll_name: String,      
    dll_full_path: String, 
}

enum UIState {
    Main,
    SelectProcess,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            name: String::new(),
            age: 0,
            selected_process: None,
            ui_state: UIState::Main,
            processes: Vec::new(),
            search_query: String::new(), 
            dll_name: String::new(),      
            dll_full_path: String::new(),
        }
    }
}



unsafe fn get_memory_usage(pid: DWORD) -> Option<u64> {
    let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if h_process.is_null() {
        return None;
    }

    let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
    if GetProcessMemoryInfo(h_process, &mut counters, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32) != 0 {
        CloseHandle(h_process);
        Some(counters.PagefileUsage as u64) // Utilisation de la mémoire avec PagefileUsage
    } else {
        CloseHandle(h_process);
        None
    }
}


impl MyApp {
    fn fetch_processes(&mut self) {
        const MAX_PROCESSES: usize = 1024;
        let mut processes: [DWORD; MAX_PROCESSES] = [0; MAX_PROCESSES];
        let mut cb_needed = 0;
    
        unsafe {
            if EnumProcesses(
                processes.as_mut_ptr(),
                (MAX_PROCESSES * std::mem::size_of::<DWORD>()) as u32,
                &mut cb_needed,
            ) != 0
            {
                let num_processes = cb_needed as usize / std::mem::size_of::<DWORD>();
                self.processes.clear();
    
                for &pid in &processes[..num_processes] {
                    if let Some(memory_usage) = get_memory_usage(pid) {
                        let h_process = OpenProcess(
                            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            0,
                            pid,
                        );
    
                        if !h_process.is_null() {
                            let mut h_mod: HMODULE = null_mut();
                            let mut cb_needed = 0;
    
                            if EnumProcessModules(
                                h_process,
                                &mut h_mod,
                                std::mem::size_of::<HMODULE>() as u32,
                                &mut cb_needed,
                            ) != 0
                            {
                                let mut process_name = vec![0u8; 256];
                                if GetModuleBaseNameA(
                                    h_process,
                                    h_mod,
                                    process_name.as_mut_ptr() as *mut i8,
                                    process_name.len() as u32,
                                ) != 0
                                {
                                    let process_name = String::from_utf8_lossy(&process_name)
                                        .trim_end_matches(char::from(0))
                                        .to_string();
                                    self.processes.push(Process { pid, name: process_name, byte: memory_usage as f64 });
                                }
                            }
                            CloseHandle(h_process);
                        }
                    }
                }
    
               
                self.processes.sort_by(|a, b| b.byte.partial_cmp(&a.byte).unwrap_or(std::cmp::Ordering::Equal));
            }
        }
    }
    
    

    fn filtered_processes(&self) -> Vec<Process> {
        let query = self.search_query.to_lowercase();
        self.processes.iter()
            .filter(|process| process.name.to_lowercase().contains(&query))
            .cloned() 
            .collect()
    }
}

impl App for MyApp {
    fn update(&mut self, lfx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.ui_state {
            UIState::Main => self.show_main_ui(lfx),
            UIState::SelectProcess => self.show_select_process_ui(lfx),
        }
    }
}

impl MyApp {
    fn show_main_ui(&mut self, lfx: &egui::Context) {
        egui::CentralPanel::default().show(lfx, |ui| {
            ui.heading("DLL injector");



            if ui.button("Select Process").clicked() {
                self.ui_state = UIState::SelectProcess;
                self.fetch_processes();
            }

            if let Some(process) = &self.selected_process {
                ui.label(format!("Process: {} [PID: {}]", process.name, process.pid));
            }

            ui.separator();

            if ui.button("Select DLL to inject").clicked() {
                if let Some(path) = FileDialog::new().add_filter("DLL", &["dll"]).pick_file() {
                    self.dll_full_path = path.display().to_string();
                    self.dll_name = path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                }
            }
            
  
            ui.label(format!("Dll name: {}", self.dll_name));
            if self.selected_process.is_some() && !self.dll_name.is_empty() {
                if let Some(process) = &self.selected_process {
                    if ui.button("Inject").clicked() {
                        
                        unsafe {
        
        
                    
                            let process_handle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, process.pid);
                            if process_handle.is_null() {
                                println!("Failed to open process.");
                                return;
                            }
                    
                            let dll_path = CString::new(self.dll_full_path.clone()).unwrap();
                            let dll_path_len = dll_path.to_bytes().len() + 1;
                    
                            let remote_mem = VirtualAllocEx(
                                process_handle,
                                ptr::null_mut(),
                                dll_path_len as usize,
                                MEM_COMMIT,
                                PAGE_READWRITE,
                            );
                            if remote_mem.is_null() {
                                println!("Failed to allocate memory in target process.");
                                CloseHandle(process_handle);
                                return;
                            }
                    
                    
                            let result = WriteProcessMemory(
                                process_handle,
                                remote_mem,
                                dll_path.as_ptr() as *const _,
                                dll_path_len as usize,
                                ptr::null_mut(),
                            );
                            if result == 0 {
                                println!("Failed to write to process memory.");
                                CloseHandle(process_handle);
                                return;
                            }
                    
                           
                            let kernel32 = winapi::um::libloaderapi::GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr());
                            let load_library = winapi::um::libloaderapi::GetProcAddress(kernel32, CString::new("LoadLibraryA").unwrap().as_ptr());
                    
                          
                            let remote_thread = CreateRemoteThread(
                                process_handle,
                                ptr::null_mut(),
                                0,
                                Some(std::mem::transmute(load_library)),
                                remote_mem,
                                0,
                                ptr::null_mut(),
                            );
                            if remote_thread.is_null() {
                                eprintln!("Failed to create remote thread.");
                                CloseHandle(process_handle);
                                return;
                            }
                    
                            
                            WaitForSingleObject(remote_thread, INFINITE);
                    
                    
                            CloseHandle(remote_thread);
                            CloseHandle(process_handle);
                        }
                        
                    }
                }
            }
            
        });
    }

    fn show_select_process_ui(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Select a Process");

            ui.horizontal(|ui| {
                ui.label("Search: ");
                ui.text_edit_singleline(&mut self.search_query); 
            });

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("process_grid").striped(true).show(ui, |ui| {
                    let filtered_processes = self.filtered_processes(); 
                    for process in filtered_processes {
                        ui.horizontal(|ui| {
                            ui.label(format!("[{} | {}]", process.pid, process.name));
                            if ui.button("Select").clicked() {
                                self.selected_process = Some(process.clone());
                                self.ui_state = UIState::Main;
                            }
                        });
                        ui.end_row();
                    }
                });
            });

            if ui.button("Cancel").clicked() {
                self.ui_state = UIState::Main;
            }
        });
    }
}

fn main() {
    let options = NativeOptions {
        initial_window_size: Some(egui::vec2(300.0, 500.0)), 
        min_window_size: Some(egui::vec2(300.0, 500.0)), 
        max_window_size: Some(egui::vec2(300.0, 500.0)),
        ..Default::default()
    };

    let app = MyApp::default();

    eframe::run_native(
        "DLL Injector by w0l6 https://github.com/w0l6",
        options,
        Box::new(|_cc| Box::new(app)),
    );
}
