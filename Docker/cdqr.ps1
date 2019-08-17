#! /usr/bin/pwsh
$ErrorActionPreference = "Stop"

$cdqr_version="5.1.0.1"
$cur_dir=Get-Location
$docker_network=$env:DOCKER_NETWORK
$timesketch_conf=$env:TIMESKETCH_CONF
$timesketch_server_ipaddress=$env:TIMESKETCH_SERVER_IPADDRESS
$docker_args="docker run"
$custom_args=@()

# Set the docker network (if any) to use
if ( $docker_network ) {
  echo "Validating the Docker network exists: $docker_network"
  $test = docker network ls | findstr $docker_network | %{ $_.Split(" ")[8]; }
  if ( $test ) {
    echo "Connecting CDQR to the Docker network: $docker_network"
    $docker_args="$docker_args --network $docker_network "
  }
  else {
    echo "Docker network $docker_network does not exist, quitting"
    echo "Exiting"
    exit
  }
}
else {
  echo "Assigning CDQR to the host network"
  echo "The Docker network can be changed by modifying the `"DOCKER_NETWORK`" environment variable"
  echo "Example (default Skadi mode): `$env:DOCKER_NETWORK = `"host`""
  echo "Example (use other Docker network): `$env:DOCKER_NETWORK = `"skadi-backend`""
  $docker_args="$docker_args --network host "
}

# Parse the arguments
foreach ($i in $args) {
    # If it's timesketch add the timesketch config file mapping
    if ( $i -eq "--es_ts" ) {
      while ($timesketch_conf -eq $null){
        echo "TimeSketch default configuration file must be set. This can be done with an Environment variable."
        echo "The default configuration is the absolute path to Skadi\Docker\timesketch\timesketch_default.conf."
        echo "Example with Skadi git repo in `"C:\GitHub\Skadi`"): `$env:TIMESKETCH_CONF = `"C:\GitHub\Skadi\Docker\timesketch\timesketch_default.conf`""
        echo ""
        $timesketch_conf = read-host "Enter the location of the TimeSketch configuration file to use in this operation "
        if (-not(test-path $timesketch_conf)){
          Write-host "Invalid file path, re-enter."
          $timesketch_conf = $null
        }
        elseif ((get-item $timesketch_conf).psiscontainer){
          Write-host "Source must be a file, re-enter."
          $timesketch_conf = $null
        }
      }
      if ( $timesketch_server_ipaddress -eq $null) {
          $timesketch_server_ipaddress = '127.0.0.1'
      }
      $docker_args="$docker_args --add-host=elasticsearch:$timesketch_server_ipaddress --add-host=postgres:$timesketch_server_ipaddress -v '${timesketch_conf}:/etc/timesketch.conf'"
    }
    # If it's an input file/dir (denoted by "in:" then resolve absolute path)
    if ( $i.SubString(0,3) -eq "in:" ) {
      $input_path=$i.SubString(3,$i.length - 3)
      $input_path_full=Resolve-Path -Path $input_path
      $docker_input_path="$input_path_full".SubString(2,"$input_path_full".length - 2).Replace("\","/")
      $docker_args+=" -v '${input_path_full}:/data$docker_input_path'"
      $custom_args+="'/data$docker_input_path'"
    }
    # If it's an output file/dir (denoted by "out:" then resolve absolute path)
    elseif ( $i.SubString(0,4) -eq "out:" ) {
      $output_path=$i.SubString(4,$i.length - 4)
      If(!(test-path $output_path))
      {
            New-Item -ItemType Directory -Force -Path $output_path | Out-Null
      }
      $output_path_full=Resolve-Path -Path $output_path
      $docker_output_path="$output_path_full".SubString(2,"$output_path_full".length - 2).Replace("\","/")
      $docker_args+=" -v '${output_path_full}:/output$docker_output_path'"
      $custom_args+="'/output$docker_output_path'"
    }
    else {
      $custom_args+=$i
    }
}
$final_command="$docker_args aorlikoski/cdqr:$cdqr_version -y $custom_args"
$final_command
iex $final_command
