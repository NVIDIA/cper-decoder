project('cper-proj', 'cpp',default_options:['default_library=static'])
incdir = include_directories('include')
nlohmann_json_dep = dependency('nlohmann_json', version: '>=3.11.2', include_type: 'system')
executable('cperparse', 'main.cpp', dependencies: nlohmann_json_dep, include_directories : incdir)
