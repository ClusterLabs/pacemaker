# OSS-Fuzz integration

The fuzzers in this folder are used for our [OSS-Fuzz](https://github.com/google/oss-fuzz)
integration.

To run this, you can follow the steps:

```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py build_fuzzers pacemaker
python3 infra/helper.py run_fuzzer pacemaker utils_fuzzer
```


## OSS-Fuzz logic

The corresponding logic for Pacemaker on OSS-Fuzz can be found [here](https://github.com/google/oss-fuzz/tree/master/projects/pacemaker)
