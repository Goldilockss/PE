# PE
PE common operations

1.所读PE文件中一处存在数据**0D0D0A**，Windows在读文件时会处理成**0D0A**，丢失其中一个**0D**，<br>原因在于Windows处理该数据时,会**将0A写成0D0A**，对应ASCII为**\r\n**。<br>

> - 解决办法:将文件的***读写模式由"r","w"改为"rb","wb"***。
