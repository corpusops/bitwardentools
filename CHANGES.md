CHANGES
---------

1.0 (unreleased)
~~~~~~~~~~~~~~~~~~
- Nothing changed yet


Cut a release
----------------

```sh
sed -i -re "s/version = \".*\"/version = \"$version\"/g" setup.py
git commit -m "release $version" setup.py
git tag $version
git push --tags
```

