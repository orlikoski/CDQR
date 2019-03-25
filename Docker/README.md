# CDQR Docker
The CDQR docker is a docker image with CDQR and all of the dependencies installed.

The docker itself is stored on DockerHub at https://hub.docker.com/r/aorlikoski/cdqr. The docker can be used by `docker run aorlikoski/cdqr`.

# Skadi Compatibility
Due to the complexity of using docker a helper bash script `cdqr` was created. It was made to work specifically on the Skadi server environment. It can be easily modified to work in any environment.

# Command Line Changes
It is not required to use the `cdqr` bash script to make `aorlikoski/cdqr` work but it makes the transition much easier. That said, there is one critical difference in the commands used with the bash script `cdqr` vs the original python `cdqr.py`. The path to the data being processed (input) and the path to the output folder (output) are parsed differently in the bash script.

_TL;DR_ use `in:` and `out:` to specify the input and output paths. The `-y` flag to accept default answers to all CDQR questions is added automatically by the script at run time. _This is important since the process will fail if any user input is required._  

`cdqr` is a transaltion script that does the heavy lifting of volume mapping and networking for docker.  

### How it Works
Helper Script Command  
`cdqr in:winevt.zip out:Results -z --max_cpu`  

Same Command Manually  
```docker run   -v /etc/hosts:/etc/hosts:ro   --network host -v /home/skadi/winevt.zip:/home/skadi/winevt.zip -v /home/skadi/Results:/home/skadi/Results aorlikoski/cdqr:4.4.0 -y /home/skadi/winevt.zip /home/skadi/Results -z --max_cpu```  

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

