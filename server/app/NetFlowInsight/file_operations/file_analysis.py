import subprocess, os
from flask import flash
import magic
from .result_generation import Scheduler
import hashlib
from multiprocessing import Queue
import threading





def run_analysis(file_path,pcap_directory, api_key):
    results_input_queue = Queue()
    results_output_queue = Queue()
    NUMBER_OF_THREADS = 8
    results_workers_threads = []

    file_paths = []
    mime_types = []
    file_results = []
    filenames = []
    extension_types = []

    

    for i in range(NUMBER_OF_THREADS):
        scheduler = Scheduler(input_queue = results_input_queue, output_queue = results_output_queue, api_key = api_key)
        results_workers_threads.append(scheduler)


    
    script_path = "/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek"
    command = ['zeek', '-C', '-r', file_path, script_path]
    try:
        os.chdir(pcap_directory)
        subprocess.run(command, check=True)

        file_analysis_path = os.path.join(pcap_directory,'extract_files')


        if os.path.exists(file_analysis_path):
            for item in os.listdir(file_analysis_path):
                item_path = os.path.join(file_analysis_path,item)
                results_input_queue.put(item_path)


            for i in range(NUMBER_OF_THREADS):
                results_input_queue.put("DONE")

            

            for i in range(len(results_workers_threads)):
                results_workers_threads[i].join()
            
            while True:
                if results_output_queue.empty():
                    break
                item_path, mime_type, analysis, filename, extension_type = results_output_queue.get()
                print(mime_type)
                file_paths.append(item_path)
                mime_types.append(mime_type)
                file_results.append(analysis)
                filenames.append(filename)
                extension_types.append(extension_type)

            flash("Analysis completed successfully.", category='success')


            return file_analysis_path, file_paths, mime_types, file_results, filenames, extension_types
        else:
            return False, False, False, False, False, False
                
    except subprocess.CalledProcessError as e:
        flash(f'{e}')
    
    




    