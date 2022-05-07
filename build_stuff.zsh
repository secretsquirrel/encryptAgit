rm -rf build/
rm -rf dist/
rm -rf encryptAgit/src/encryptAgit.egg-info

python3 setup.py sdist bdist_wheel

python3 -m twine upload --verbose dist/*
