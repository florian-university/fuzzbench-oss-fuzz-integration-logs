Results of trying to integrate and test-run all current OSS-Fuzz projects into Fuzzbench, using AFL. In the folder 
`integrate_all_afl_2`, there is a `main_log` containing logs from my script and the folders for each integrated experiment
(that existed) and their respective log files and out directory (if it built). 

Out of 569 projects, I was not able to test 469 projects, since they did not exist before the 25th of August 2021.
However, I was able to test the remaining 100 projects. From these 75 failed and 27 started fuzzing. For 2 projects, 
some fuzz targets worked, while others failed. I appended the projects, fuzz targets, commit hashes and dates in 
`report.py`. 

Most error messages are in the form of `ERROR: gcr.io/fuzzbench/builders/afl/project_fuzztarget:latest: not found` but 
there are many others. Unfortunately, neither do I have the knowledge nor the time to analyze these and give you more 
insight (still doing by bachelor). 75 failing libs are still a lot and might also just fail because the old OSS-Fuzz 
projects are outdated. I still thought that this test run and the log files might be valuable to you. If not that's 
also fine.

Anyway thank you and stay healthy :) I'll be the first one to test the OSS-Fuzz integration, once Fuzzbench runs on 
20.04. Keep up the good work, it's absolutely crucial for the evaluation of fuzzers.


PS: `pffft_fuzzers_seed_corpus.zip` is not in the repo cause its too big

