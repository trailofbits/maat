# Copy maat python module locally
cp $1 .
# Run python tests
pytest
# Remove local copy of python module
rm ./$(basename $1)