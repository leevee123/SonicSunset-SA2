@call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
@set "SF_WEIGHTED_INCLUDES=/I weighted-stage/prepared/src /I C:\decomp\SonicFantasy-master\src /I C:\decomp\SonicFantasy-master\src\Misc /I C:\decomp\SonicFantasy-master\src\Importers\GameCube"
@cl /nologo /std:c++latest /EHsc /O2 /fp:strict /W4 /WX %SF_WEIGHTED_INCLUDES% /c weighted-stage/prepared/src/Importers/SA2/ModelVertexTransform.cpp /Fo:weighted-stage/weighted_transform.obj
@if errorlevel 1 exit /b 1
@cl /nologo /std:c++latest /EHsc /O2 /fp:strict /W4 /WX %SF_WEIGHTED_INCLUDES% /c weighted_data_check_iso.cpp /Fo:weighted-stage/weighted_data_check_iso.obj
@if errorlevel 1 exit /b 1
@link /nologo weighted-stage/weighted_transform.obj weighted-stage/weighted_data_check_iso.obj rel-validation/sa2_prs.obj rel-validation/shadow_prs.obj rel-validation/gc_disc.obj /OUT:weighted-stage/weighted_data_check_iso.exe
@exit /b %errorlevel%
