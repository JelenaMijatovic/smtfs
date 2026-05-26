#! /bin/bash

if [ $# -lt 3 ]; then
    echo "Usage: smttag [-r] tags... -f files...|-d directories..."
    exit 1
fi

declare ACT="-n"
declare FILE=0
declare DIR=0
declare tags=()
declare files=""
declare dirs=()

for ((i = $#-1; i >= 0; i--)); {
    case "${BASH_ARGV[$i]}" in 
    "-r" ) ACT="-x";;
    "-f" ) FILE=1 DIR=0;;
    "-d" ) DIR=1 FILE=0;;
    *) 
    if [ $FILE -eq 0 -a $DIR -eq 0 ]; then
        tags+=(${BASH_ARGV[$i]})
    elif [ $FILE -eq 1 -a -e ${BASH_ARGV[$i]} ]; then
        files+="${BASH_ARGV[$i]}"
        files+=" "
    elif [ $DIR -eq 1 -a -d ${BASH_ARGV[$i]} ]; then
        dirs+=(${BASH_ARGV[$i]})
    fi;;
    esac
}

if [ "$files" != "" ]; then
    for tag in ${tags[*]}; do
        setfattr $ACT $tag $files
    done
fi

for dir in ${dirs[*]}; do
    for file in $dir/*; do 
        for tag in ${tags[*]}; do
            setfattr $ACT $tag $file
        done
    done
done
