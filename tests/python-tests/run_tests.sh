# Usage: run_tests.sh <maat_python_module.so> <sleigh_spec_dir>
# Copy maat python module locally
cp $1 .
export MAAT_SLEIGH_DIR=$2
# Run python tests
python3 -m pytest .
status=$?
# Remove local copy of python module
rm ./$(basename $1)
exit $status