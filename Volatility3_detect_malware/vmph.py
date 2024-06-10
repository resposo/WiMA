from volatility3.framework import contexts, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.automagic import stacker, windows
from volatility3.plugins.windows import pslist, vadinfo

def get_vad_info(memory_dump, pid):
    # Initialize a volatility context
    context = contexts.Context()
    base_config_path = "plugins"
    single_location = f"file:{memory_dump}"

    # Set up configuration
    context.config['automagic.LayerStacker.single_location'] = single_location

    # Initialize the required automagic modules
    automagic_modules = [
        stacker.LayerStacker,
        windows.WindowsKernelModule
    ]

    # Run automagic to populate context with layers and symbols
    progress_callback = interfaces.progress.ProgressCallback()
    for automagic in automagic_modules:
        automagic_instance = automagic(context)
        automagic_instance.run(progress_callback)

    # Scan for processes and find the specified PID
    layer_name = context.layers.list()[0]
    processes = list(pslist.PsList.list_processes(context, layer_name, base_config_path))

    process = next((proc for proc in processes if proc.UniqueProcessId == pid), None)

    if process is None:
        raise ValueError(f"Process with PID {pid} not found.")

    vad_info_list = []

    # Walk the VAD tree
    for vad in vadinfo.VadInfo.list_vads(context, process):
        vad_info = {
            "Start": hex(vad.get_start()),
            "End": hex(vad.get_end()),
            "Protection": vad.get_protection().get("protection", "UNKNOWN"),
            "Tag": vad.get_tag()
        }
        vad_info_list.append(vad_info)

    return vad_info_list

# Example usage
if __name__ == "__main__":
    memory_dump_path = r"C:\Users\user\Desktop\메모리\volatility3-2.4.1\vm_default.dmp"  # Replace with the path to your memory dump file
    target_pid = 8688  # Replace with the target process ID

    try:
        vad_info_list = get_vad_info(memory_dump_path, target_pid)
        for vad in vad_info_list:
            print(vad)
    except Exception as e:
        print(f"An error occurred: {e}")
