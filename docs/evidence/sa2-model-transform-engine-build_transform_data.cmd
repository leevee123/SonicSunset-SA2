@call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
@cl /nologo /std:c++latest /EHsc /O2 /fp:strict /W4 /WX /I transform-stage/prepared/src /I C:\decomp\SonicFantasy-master\src\Misc transform-stage/prepared/src/Importers/SA2/ModelVertexTransform.cpp transform_data_check.cpp /Fo:transform-stage/ /Fe:transform-stage/transform_data_check.exe
@exit /b %errorlevel%
