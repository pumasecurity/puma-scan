#!/bin/bash

# Command usage menu
usage(){
  echo -e "\nUSAGE: 
		`basename $0` -s <path/to/code> [-e project.csproj,test.csproj] [ -h ]

Options:
	-s <path/to/src>		Directory containg the source code to analyze
	-e <project.csproj>		Project(s) to to exclude from the scan.
	-h				Display this help menu.
"
echo ""
exit
}

while getopts "hs:e:" OPTION; do
   case $OPTION in
     h )
        usage
        exit 1
        ;;
     s )
        SOURCE=$OPTARG
        echo "Source directory set to $SOURCE"
        ;;
     e )
        EXCLUDE=$OPTARG
		IFS=',' read -ra EXCLUDE_ITEMS <<< "$EXCLUDE"
		echo "Exclude set to $EXCLUDE"
		;;
     : )
        echo -e "\nERROR!  -$OPTARG requires an argument\n"
        usage
        exit 1
        ;;
     ? )
        echo -e "\nERROR! Invalid option"
        usage
        exit 1
        ;;
   esac
done

if [[ "" == $SOURCE ]] ; then
	usage; 
	exit 1;
fi


# Change to source directory
echo Chaning directory to $SOURCE
cd $SOURCE

# Loop through projects and add code analysis 2.9 / puma scan package
for project in `find . -iname "*.csproj" -type f`; do
	
	# Check exclude projects
	for e in "${EXCLUDE_ITEMS[@]}"; do
		#echo Exclude: "./$e"
		#echo Project: $project

		if [[ "./Puma.Security.Rules.Test/*" ~= "$project" ]]; then
			echo "Excluding project or path $project"
		fi
	done
	#echo "Analyzing project $project"
done


