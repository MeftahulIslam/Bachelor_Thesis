import openai, subprocess, json, time, os, magic, threading, hashlib
from multiprocessing import Queue




#openai.api_key="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"




class Scheduler(threading.Thread):
    def __init__(self, input_queue, output_queue, api_key, **kwargs):
        super(Scheduler, self).__init__(**kwargs)
        self._api_key = api_key
        self._input_queue = input_queue
        self._output_queue = output_queue
        print("starting a thread...")
        self.start()

    def run(self):
        while True:
            _item_path = self._input_queue.get()
            print(f"got one item {_item_path}")
            if _item_path == "DONE":
                break
            result_generation = Result_Generation(_item_path, self._api_key)
            mime_type, analysis, filename, extension_type = result_generation.file_result_generation()
            results = [_item_path, mime_type, analysis, filename, extension_type]
            print(results)
            self._output_queue.put(results) 





   


class Result_Generation():
    def __init__(self, item_path, api_key):
        self._item_path = item_path
        self._api_key = api_key

    def file_result_generation(self):
        #file_paths.append(item_path)
        file_mime_type = magic.Magic(mime=True)
        mime_type = file_mime_type.from_file(self._item_path)
        #mime_types.append(mime_type)

        with open(self._item_path, 'rb') as file:
            chunk_size = 4096
            hasher = hashlib.sha256()
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        filename = str(hasher.hexdigest())
        #filenames.append(str(hasher.hexdigest()))

        extension_type = self._get_extension_type(mime_type)
        #extension_types.append(extension_type)
        parts = mime_type.split('/')
        if parts[0] == 'text' or parts[0] == 'application':
            analysis = self._analyze_file_hybrid_analysis(parts[0])
        else:
            analysis = f"This is a {extension_type} file"
        return mime_type, analysis, filename, extension_type
    
    def _get_extension_type(self, mime_type):
        parts = mime_type.split('/')
        return parts[1]
    
    
    def _analyze_file_openai(self):
        openai.api_key = self._api_key
        analysis = "Something went wrong! Unknown error!"
        try:
            with open(self._item_path, 'r') as file:
                file_contents = file.read()

            prompt = f"Analyze the contents of this file:\n{file_contents}\n\nExplain what type of script it is and what the script is doing in summary and provide a verdict if the contents of the file are malicious."

            response = openai.Completion.create(
                engine = 'gpt-3.5-turbo-instruct',
                prompt = prompt,
                max_tokens = 200,
                n = 1,
                stop = None,
                temperature = 0.7
            )

            analysis = response.choices[0].text.strip()
            print(f'1 file analyzed by openai')
            return analysis


        except Exception as e:
            print(f'{e}')
            return analysis



            
    def _analyze_file_hybrid_analysis(self,mime_type):
            openai.api_key = self._api_key
            analysis = "Something went wrong! Unknown error!"
            print("started analyzing...")
            vxapi_path = '/opt/app/VxAPI-master/vxapi.py'
            command = ['python3', vxapi_path, 'scan_file', self._item_path, 'all']
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                output = result.stdout.strip()
                data = json.loads(output)
                sha256 = data["sha256"]
                time.sleep(5)

                command = ['python3', vxapi_path, 'overview_get', sha256]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                print("got the fileresult...")
                output = result.stdout.strip()
                data = json.loads(output)
                prompt = f"""Give me brief report in this format:\n
                            Scores:\n
                            \nMetadefender:
                            \nVirusTotal:
                            \nCrowdStrike Falcon Static Analysis (ML):
                            \nFinal Verdict:
                            {data}"""

                response = openai.Completion.create(
                    engine = 'gpt-3.5-turbo-instruct',
                    prompt = prompt,
                    max_tokens = 200,
                    n = 1,
                    stop = None,
                    temperature = 0.7
                )

                analysis = response.choices[0].text.strip()  
                if "Final Verdict: Malicious" in analysis:
                    if mime_type == "text":
                        open_ai_analysis = self._analyze_file_openai()
                        analysis = analysis + "\n\nOpenAi Analysis:\n"+ open_ai_analysis
                        print('1 file successfully analyzed by Hybrid Analysis')
                        return analysis   
                return analysis
            
            except openai.error.AuthenticationError as e:
                analysis = """Incorrect OpenAI API key provided! \nCouldn't Analyze! 
                \nPlease change the OpenAI API key from your Profile!"""
                return analysis
            
            except Exception as e:
                print(f'{e}')
                return analysis