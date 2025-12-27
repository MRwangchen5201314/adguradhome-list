#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home Filter Optimizer
优化AdGuard Home规则：去重、域名收敛、格式标准化
"""

import re
import os
import sys
import json
import yaml
from collections import defaultdict
from datetime import datetime

class FilterOptimizer:
    def __init__(self, config_path='config.yml'):
        """初始化优化器"""
        self.config = self.load_config(config_path)
        self.stats = {
            'original_count': 0,
            'valid_count': 0,
            'duplicate_count': 0,
            'converged_count': 0,
            'final_count': 0,
            'start_time': datetime.now()
        }
        
    def load_config(self, config_path):
        """加载配置文件"""
        default_config = {
            'remove_invalid': True,
            'domain_convergence': True,
            'format_standardize': True,
            'supported_modifiers': [
                'domain', 'third-party', 'important', 'client', 
                'dnstype', 'dnsrewrite', 'rewrite'
            ],
            'input': {
                'source_dir': 'sources',
                'file_patterns': ['*.txt', '*.filters']
            },
            'output': {
                'optimized_file': 'output/optimized.txt',
                'statistics_file': 'output/stats.json',
                'removed_rules_log': 'output/removed.log'
            }
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config:
                        # 递归更新配置
                        self.update_config(default_config, loaded_config)
            except Exception as e:
                print(f"警告：加载配置文件失败，使用默认配置: {e}")
        
        return default_config
    
    def update_config(self, base, update):
        """递归更新配置字典"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self.update_config(base[key], value)
            else:
                base[key] = value
    
    def load_rules(self):
        """从sources目录加载所有规则文件"""
        rules = []
        source_dir = self.config['input']['source_dir']
        
        if not os.path.exists(source_dir):
            print(f"错误：源目录 {source_dir} 不存在")
            return rules
        
        # 获取所有匹配的文件
        import glob
        pattern = os.path.join(source_dir, '**', '*.txt')
        files = glob.glob(pattern, recursive=True)
        
        pattern2 = os.path.join(source_dir, '**', '*.filters')
        files.extend(glob.glob(pattern2, recursive=True))
        
        print(f"找到 {len(files)} 个规则文件")
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_rules = f.readlines()
                    rules.extend(file_rules)
                    print(f"  - 加载 {file_path}: {len(file_rules)} 条规则")
            except Exception as e:
                print(f"  - 加载失败 {file_path}: {e}")
        
        self.stats['original_count'] = len(rules)
        print(f"\n总共加载 {len(rules)} 条规则")
        return rules
    
    def normalize_rule(self, rule):
        """标准化单条规则"""
        rule = rule.strip()
        
        # 跳过空行、注释、无效规则
        if not rule or rule.startswith('!') or rule.startswith('#'):
            return None
        
        # 移除多余的空白字符
        rule = re.sub(r'\s+', ' ', rule)
        
        # 处理修饰符
        if '$' in rule:
            parts = rule.split('$', 1)
            pattern = parts[0].strip()
            modifiers = parts[1].strip()
            
            # 解析并过滤修饰符
            modifier_list = [m.strip() for m in modifiers.split(',') if m.strip()]
            valid_modifiers = []
            
            for modifier in modifier_list:
                mod_name = modifier.split('=')[0]
                if mod_name in self.config['supported_modifiers']:
                    valid_modifiers.append(modifier)
            
            if valid_modifiers:
                # 排序修饰符以确保一致性
                valid_modifiers.sort()
                rule = f"{pattern}${','.join(valid_modifiers)}"
            else:
                rule = pattern
        
        # 格式标准化：转换为 ||domain^ 格式
        if self.config['format_standardize']:
            rule = self.convert_to_pipe_format(rule)
        
        return rule
    
    def convert_to_pipe_format(self, rule):
        """转换为 ||domain^ 格式"""
        # 如果已经是 ||domain^ 格式，直接返回
        if rule.startswith('||') and rule.endswith('^'):
            return rule
        
        # 如果已经是异常规则，保持原样
        if rule.startswith('@@||') and rule.endswith('^'):
            return rule
        
        # 提取域名
        # 匹配 ||example.com^ 格式
        match = re.match(r'^\|\|([^/^$]+)\^', rule)
        if match:
            return rule
        
        # 匹配普通域名
        domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', rule)
        if domain_match:
            domain = domain_match.group(1)
            # 如果是异常规则
            if rule.startswith('@@'):
                return f"@@||{domain}^"
            else:
                return f"||{domain}^"
        
        return rule
    
    def deduplicate_rules(self, rules):
        """去重规则"""
        seen = set()
        unique_rules = []
        duplicates = []
        
        for rule in rules:
            if rule not in seen:
                seen.add(rule)
                unique_rules.append(rule)
            else:
                duplicates.append(rule)
        
        self.stats['duplicate_count'] = len(duplicates)
        print(f"去重: {len(rules)} → {len(unique_rules)} (移除 {len(duplicates)} 条重复规则)")
        
        # 保存被移除的重复规则
        if duplicates:
            self.save_removed_rules(duplicates, 'duplicates')
        
        return unique_rules
    
    def domain_convergence(self, rules):
        """域名收敛：删除父域名已拦截的子域名规则"""
        if not self.config['domain_convergence']:
            return rules
        
        # 提取域名规则
        domain_rules = {}
        other_rules = []
        
        for rule in rules:
            if rule.startswith('||') and rule.endswith('^'):
                domain = rule[2:-1]  # 移除 || 和 ^
                domain_rules[domain] = rule
            else:
                other_rules.append(rule)
        
        print(f"\n域名收敛：找到 {len(domain_rules)} 条域名规则")
        
        # 按域名长度排序（从长到短）
        sorted_domains = sorted(domain_rules.keys(), key=len, reverse=True)
        to_remove = set()
        
        # 检查每个域名是否是其他域名的子域名
        for i, domain in enumerate(sorted_domains):
            for other in sorted_domains[i+1:]:
                # 如果是子域名（例如：ads.example.com 是 example.com 的子域名）
                if domain.endswith('.' + other) or domain == other:
                    to_remove.add(domain)
                    break
        
        # 构建最终规则列表
        final_domain_rules = [domain_rules[d] for d in domain_rules if d not in to_remove]
        final_rules = other_rules + final_domain_rules
        
        self.stats['converged_count'] = len(to_remove)
        print(f"域名收敛后: {len(rules)} → {len(final_rules)} (移除 {len(to_remove)} 条冗余子域名规则)")
        
        # 保存被移除的子域名规则
        if to_remove:
            removed_subdomains = [domain_rules[d] for d in to_remove]
            self.save_removed_rules(removed_subdomains, 'subdomains')
        
        return final_rules
    
    def save_removed_rules(self, rules, reason):
        """保存被移除的规则"""
        log_file = self.config['output']['removed_rules_log']
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"移除原因: {reason}\n")
            f.write(f"移除时间: {datetime.now().isoformat()}\n")
            f.write(f"移除数量: {len(rules)}\n")
            f.write(f"{'='*50}\n\n")
            for rule in rules:
                f.write(f"{rule}\n")
    
    def save_results(self, rules):
        """保存优化结果"""
        output_file = self.config['output']['optimized_file']
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # 生成文件头
        header = f"""! Title: Optimized AdGuard Home Filters
! Description: Optimized filter list for AdGuard Home
! Version: {datetime.now().strftime('%Y%m%d%H%M%S')}
! Last Modified: {datetime.now().isoformat()}
! Optimizer: GitHub Actions Automation
! Original Rules: {self.stats['original_count']}
! Optimized Rules: {len(rules)}
! Reduction: {self.stats['reduction_percent']:.2f}%
! \n"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            for rule in sorted(rules):
                f.write(f"{rule}\n")
        
        print(f"\n优化结果已保存到: {output_file}")
    
    def save_statistics(self):
        """保存统计信息"""
        stats_file = self.config['output']['statistics_file']
        os.makedirs(os.path.dirname(stats_file), exist_ok=True)
        
        self.stats['final_count'] = self.stats['valid_count'] - self.stats['duplicate_count'] - self.stats['converged_count']
        self.stats['end_time'] = datetime.now()
        self.stats['duration_seconds'] = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        if self.stats['original_count'] > 0:
            self.stats['reduction_percent'] = (
                (self.stats['original_count'] - self.stats['final_count']) / self.stats['original_count'] * 100
            )
        else:
            self.stats['reduction_percent'] = 0
        
        # 保存为JSON
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, default=str)
        
        print(f"\n统计信息已保存到: {stats_file}")
    
    def print_statistics(self):
        """打印统计信息"""
        print("\n" + "="*60)
        print("优化统计报告")
        print("="*60)
        print(f"原始规则数: {self.stats['original_count']:,}")
        print(f"有效规则数: {self.stats['valid_count']:,}")
        print(f"重复规则数: {self.stats['duplicate_count']:,}")
        print(f"冗余子域名数: {self.stats['converged_count']:,}")
        print(f"最终规则数: {self.stats['final_count']:,}")
        print(f"减少比例: {self.stats['reduction_percent']:.2f}%")
        print(f"处理时间: {self.stats['duration_seconds']:.2f}秒")
        print("="*60)
    
    def run(self):
        """运行优化流程"""
        print("="*60)
        print("AdGuard Home Filter Optimizer")
        print("="*60)
        print(f"开始时间: {self.stats['start_time'].isoformat()}")
        print("="*60)
        
        # 1. 加载规则
        print("\n[步骤 1/5] 加载规则文件...")
        raw_rules = self.load_rules()
        
        if not raw_rules:
            print("错误：没有加载到任何规则")
            return False
        
        # 2. 标准化规则
        print("\n[步骤 2/5] 标准化规则格式...")
        normalized_rules = []
        for rule in raw_rules:
            normalized = self.normalize_rule(rule)
            if normalized:
                normalized_rules.append(normalized)
        
        self.stats['valid_count'] = len(normalized_rules)
        print(f"标准化后: {len(normalized_rules)} 条有效规则")
        
        # 3. 去重
        print("\n[步骤 3/5] 去重处理...")
        deduplicated_rules = self.deduplicate_rules(normalized_rules)
        
        # 4. 域名收敛
        print("\n[步骤 4/5] 域名收敛...")
        final_rules = self.domain_convergence(deduplicated_rules)
        
        # 5. 保存结果
        print("\n[步骤 5/5] 保存优化结果...")
        self.save_results(final_rules)
        self.save_statistics()
        
        # 打印统计
        self.print_statistics()
        
        print("\n优化完成！")
        return True

if __name__ == '__main__':
    optimizer = FilterOptimizer()
    success = optimizer.run()
    sys.exit(0 if success else 1)
