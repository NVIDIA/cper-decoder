project('cper-proj', 'cpp',default_options:['default_library=static'])
nlohmann_json_dep = dependency('nlohmann_json', version: '>=3.11.2', include_type: 'system')
CLI11_dep = dependency('CLI11')
executable('cperparse', 'main.cpp', dependencies: [ nlohmann_json_dep, CLI11_dep ])
