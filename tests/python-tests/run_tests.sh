# Copy maat python module locally
cp $1 .
# Run python tests
python3 -m pytest .
status=$?
# Remove local copy of python module
rm ./$(basename $1)
exit $status