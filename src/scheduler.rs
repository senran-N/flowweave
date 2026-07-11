/// FlowWeave 对外使用的多路径调度策略。
///
/// 当前没有通过筛选的自定义候选，只保留 NoQ 原行为作为可复现实验基线。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MultipathScheduler {
    /// 保留 NoQ 原本的低路径编号优先行为。
    #[default]
    NoqDefault,
}

impl MultipathScheduler {
    pub const CANDIDATES: [Self; 1] = [Self::NoqDefault];

    pub fn description(self) -> &'static str {
        match self {
            Self::NoqDefault => "NoQ 默认（低编号优先）",
        }
    }
}
