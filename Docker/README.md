# CDQR Docker
The CDQR docker is a docker image with CDQR and all of the dependencies installed.

The docker itself is stored on DockerHub at https://hub.docker.com/r/aorlikoski/cdqr. The docker can be used by `docker run aorlikoski/cdqr`.

## Process ZIP file (default windows parser list)
This uses the default win parser list and saves output to Results folder on host  
*cdqr in:winevt.zip out:Results -z --max_cpu*  
![](/objects/images/zip_demo.gif?)

## Use the same .plaso file but output into Kibana
This uses existing .plaso file and doesn't save the output on the host (it is ephemeral and deleted when the CDQR docker run completes)  
*cdqr in:Results/winevt.plaso --plaso_db --es_kb winevt*  
![](/objects/images/plaso_kibana.gif?)

## Use the same .plaso file but output into TimeSketch
This uses existing .plaso file and doesn't save the output on the host. This uses `/etc/timesketh.conf` on the host to pass the values it needs to insert into TimeSketch.  
*cdqr in:Results/winevt.plaso --plaso_db --es_ts winevt*  
![](/objects/images/plaso_ts.gif?)

# Skadi Compatibility
Due to do the complexity of using docker a helper bash script `cdqr` was created. It was made to work specifically on the Skadi server environment. It can be easily modified to work in any environment.

# Command Line Changes
It is not required to use `aorlikoski/cdqr` but it makes the transition much easier. That said, there is one critical difference in the commands used with the bash script `cdqr` vs the original python `cdqr.py`. The path to the data being processed (input) and the path to the output folder (output) are parsed differently in the bash script.

_TL;DR_ use `in:` and `out:` to specify the input and output paths and use the `-y` flag to accept defaults for all questions from CDQR during run time. _This is important since the process will fail if any user input is required._
