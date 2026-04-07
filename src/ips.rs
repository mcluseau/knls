use std::net::IpAddr;

pub fn parse_iter<'t>(ips: impl Iterator<Item = &'t String>) -> impl Iterator<Item = IpAddr> {
    ips.filter_map(|s| s.parse::<IpAddr>().ok())
}

pub fn parse_opt(ips: Option<&Vec<String>>) -> Vec<IpAddr> {
    let mut parsed = Vec::new();
    let Some(ips) = ips.as_ref() else {
        return parsed;
    };
    parsed.reserve(ips.len());
    parsed.extend(parse_iter(ips.iter()));
    parsed
}

pub fn parse_opt_with<I>(items: Option<&Vec<I>>, f: fn(&I) -> Option<&String>) -> Vec<IpAddr> {
    let mut parsed = Vec::new();
    let Some(items) = items.as_ref() else {
        return parsed;
    };
    parsed.reserve(items.len());
    parsed.extend(parse_iter(items.iter().filter_map(|i| f(i))));
    parsed
}
