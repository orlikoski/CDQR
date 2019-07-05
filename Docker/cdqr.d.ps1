#! /usr/bin/pwsh
$ErrorActionPreference = "Stop"

$cdqr_version="5.0.0"
$cur_dir=Get-Location
$timesketch_conf="E:\GitHub\Skadi\Docker\timesketch\timesketch_default.conf"
$docker_args="docker run -d -v C:\Windows\System32\drivers\etc\hosts:/etc/hosts:ro "
$custom_args=@()
foreach ($i in $args) {
    # If it's timesketch add the timesketch mapping
    if ( $i -eq "--es_ts" ) {
      $docker_args="$docker_args -v ${timesketch_conf}:/etc/timesketch.conf"
    }
    # If it's an input file/dir (denoted by "in:" then resolve absolute path)
    if ( $i.SubString(0,3) -eq "in:" ) {
      $input_path=$i.SubString(3,$i.length - 3)
      $input_path_full=Resolve-Path -Path $input_path
      $docker_input_path="$input_path_full".SubString(2,"$input_path_full".length - 2).Replace("\","/")
      $docker_args+=" -v ${input_path_full}:/data$docker_input_path"
      $custom_args+="/data$docker_input_path"
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
      $docker_args+=" -v ${output_path_full}:/output$docker_output_path"
      $custom_args+="/output$docker_output_path"
    }
    else {
      $custom_args+=$i
    }
}
$final_command="$docker_args aorlikoski/cdqr:$cdqr_version -y $custom_args"
$final_command
iex $final_command
# final_command="$docker_args aorlikoski/cdqr:$cdqr_version -y ${args[@]}"
