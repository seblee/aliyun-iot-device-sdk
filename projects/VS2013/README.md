windows版本注意事项
================
在使用Visual Studio进行编译过程中可能因为sdk源文件中的unix换行符造成编译错误，此时可以使用tools/convert_line_end目录下的convertLR.sh工具在linux环境下转换为windows换行符。