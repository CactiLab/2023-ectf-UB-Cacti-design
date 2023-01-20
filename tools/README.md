If someone uses windows and gets an error `Unknown option: -` when trying to interact with the board, here is the solution.
- Locate the position of `run_shell` in `ectf_tools/run.py`, you will find one line of code containing `{tag}`. Such as 
  ```c
  f" {tag} ./package_tool --package-name {package_name}"
  ```
- Add `python3` between `{tag}` and `./package_tool`. This line of code will change to 
  ```c
  f" {tag} python3 ./package_tool --package-name {package_name}"
  ```
- Then it works.