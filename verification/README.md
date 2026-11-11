独立验收说明

冻结提交：https://github.com/9873199/pefile-certificate-audit/commit/efb1cb64c1740b9bd564bd83be2d93dbf0ff2c54
实际解释器：3.14.3 (tags/v3.14.3:323c59a, Feb  3 2026, 16:04:56) [MSC v.1944 64 bit (AMD64)]

从冻结提交检出源码，用environment-reviewed.json列出的真实Python和依赖运行各verification目录的*-command.json；pe_adapter.py只映射原生字段和异常类型，未补结构校验。正常夹具的dwLength包含零填充，依据format-reference-r1记录的微软原文；不以有争议的未填充长度拒绝扣分。记录数上限用测试里的monkeypatch显式降低模块常量，库没有max_records公开参数，不要求该参数。主验收23项和controls7项分别保存；observations-r1直接输出原生对象，退出0仅表示诊断执行完，不能当成两个问题通过。baseline-r1把初始Git提交archive到独立缓存目录，53通过/11缺语料失败/1跳过/529子测试通过；初始比较器因LF/CRLF断言停止，baseline-comparison-r2明确记录双方原始Hash、AST及Git对照，不改原日志。完整最终回归为102通过/11缺语料失败/1跳过/529子测试通过。测试不执行PE文件、不联网校验证书。录屏为另写的验证控制台，不是模型生成的业务UI。

每组目录内的 *-command.json 保留真实参数、工作目录、PYTHONPATH、退出码和原始日志位置；test-results.json 与 JUnit XML 保留完整成绩。跨机器运行时把这些绝对路径映射到同一冻结 checkout 和自己的缓存目录，所有 --basetemp、XML 和构建输出均放在缓存里。依赖版本见 environment-reviewed.json。
这些材料在模型单轮结束后生成，与原轨内测试分开，不代表项目方质检通过。原轨和视频只放各自的飞书附件。


冻结产物提交：https://github.com/9873199/pefile-certificate-audit/commit/efb1cb64c1740b9bd564bd83be2d93dbf0ff2c54
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
