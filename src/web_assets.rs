// Self-contained styling keeps the management UI usable on IPTV-only networks.
pub(crate) const BASE_CSS: &str = r#"
:root{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#212529;background:#f8f9fa;line-height:1.5}*{box-sizing:border-box}body{margin:0;background:#f8f9fa}a{color:#0d6efd;text-decoration:none}a:hover{text-decoration:underline}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#d63384}.container{width:min(1140px,calc(100% - 32px));margin:0 auto}.pb-5{padding-bottom:3rem}.mb-0{margin-bottom:0}.mb-1{margin-bottom:.25rem}.mb-2{margin-bottom:.5rem}.mb-4{margin-bottom:1.5rem}.mb-5{margin-bottom:3rem}.mt-3{margin-top:1rem}.mt-4{margin-top:1.5rem}.mt-5{margin-top:3rem}.me-1{margin-right:.25rem}.me-2{margin-right:.5rem}.me-3{margin-right:1rem}.ms-2{margin-left:.5rem}.ms-auto{margin-left:auto}.mx-2{margin-left:.5rem;margin-right:.5rem}.p-3{padding:1rem}.p-4{padding:1.5rem}.px-0{padding-left:0;padding-right:0}.py-3{padding-top:1rem;padding-bottom:1rem}.small{font-size:.875rem}.h4{font-size:1.5rem}.fw-bold{font-weight:700}.fw-normal{font-weight:400}.text-muted{color:#6c757d}.text-success{color:#198754}.text-primary{color:#0d6efd}.text-info{color:#087990}.text-white{color:#fff}.text-center{text-align:center}.text-uppercase{text-transform:uppercase}.text-truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.text-decoration-none{text-decoration:none}.bg-dark{background:#212529}.bg-white{background:#fff}.bg-light{background:#f8f9fa}.bg-primary{background:#0d6efd}.bg-success{background:#198754}.bg-info{background:#0dcaf0}.bg-warning{background:#ffc107}.bg-secondary{background:#6c757d;color:#fff}.bg-primary-subtle{background:#cfe2ff}.bg-info-subtle{background:#cff4fc}.border{border:1px solid #dee2e6}.border-primary-subtle{border-color:#9ec5fe}.border-info-subtle{border-color:#9eeaf9}.border-end{border-right:1px solid #dee2e6}.rounded-pill{border-radius:999px}.rounded-3{border-radius:.5rem}.d-flex{display:flex}.flex-wrap{flex-wrap:wrap}.flex-grow-1{flex-grow:1}.gap-2{gap:.5rem}.align-items-center{align-items:center}.justify-content-between{justify-content:space-between}.h-100{height:100%}.overflow-hidden{overflow:hidden}.row{display:flex;flex-wrap:wrap;margin:-.75rem}.row>*{padding:.75rem;width:100%}.navbar{display:flex;padding:.75rem 0}.navbar .container{display:flex;align-items:center}.navbar-brand{color:#fff;font-size:1.25rem;font-weight:700}.navbar-nav{display:flex;gap:1rem}.nav-link{color:#cfd3d7}.nav-link.active,.nav-link:hover{color:#fff}.card{background:#fff;border-radius:12px;box-shadow:0 .125rem .25rem rgba(0,0,0,.075)}.card-header{padding:1rem 1.25rem;border-bottom:1px solid #eee}.card-body{padding:1.25rem}.list-group{display:flex;flex-direction:column}.list-group-item{display:flex;color:#212529;border-bottom:1px solid #eee}.list-group-item:last-child{border-bottom:0}.badge{display:inline-block;padding:.35em .65em;border-radius:.375rem;font-size:.75em}.btn{display:inline-block;padding:.375rem .75rem;border:1px solid transparent;border-radius:.375rem;background:#fff;cursor:pointer}.btn-sm{padding:.25rem .5rem;font-size:.875rem}.btn-outline-primary{border-color:#0d6efd;color:#0d6efd}.btn-outline-success{border-color:#198754;color:#198754}.btn-outline-info{border-color:#0dcaf0;color:#087990}.btn-outline-warning{border-color:#ffc107;color:#664d03}.btn-outline-dark{border-color:#212529;color:#212529}.btn-outline-secondary{border-color:#6c757d;color:#6c757d}.btn-warning{background:#ffc107;color:#212529}.form-control{display:block;width:100%;padding:.5rem .75rem;border:1px solid #ced4da;border-radius:.375rem;background:#fff}.table-responsive{overflow-x:auto}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:.75rem;border-bottom:1px solid #dee2e6;text-align:left}.table-hover tbody tr:hover{background:#f4f6f8}.list-unstyled{padding-left:0;list-style:none}.stat-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center}.action-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;margin-bottom:1rem}.search-wrap{position:relative}.search-wrap input{padding-left:1rem}#channelTable{min-width:850px}
.bi{display:inline-block;width:1em;height:1em;vertical-align:-.125em;background-color:currentColor;-webkit-mask:var(--bi-icon) center/contain no-repeat;mask:var(--bi-icon) center/contain no-repeat}
.bi-broadcast{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='12' cy='12' r='2' fill='black'/%3E%3Cpath d='M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2'/%3E%3C/svg%3E")}
.bi-file-earmark-code{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 2h8l4 4v16H6zM14 2v5h4M10 11l-2 2 2 2M14 11l2 2-2 2'/%3E%3C/svg%3E")}
.bi-arrow-clockwise{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 6v5h-5M19 11a7 7 0 1 0 .1 5'/%3E%3C/svg%3E")}
.bi-search{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m20 20-4-4'/%3E%3C/svg%3E")}
.bi-list-stars{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Cpath d='M10 6h10M10 12h10M10 18h10M5 4.5l.5 1 1 .2-.8.8.2 1.1-1-.5-1 .5.2-1.1-.8-.8 1-.2zM4 12h2M4 18h2'/%3E%3C/svg%3E")}
.bi-info-circle{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='12' cy='12' r='9'/%3E%3Cpath d='M12 11v5M12 8h.01'/%3E%3C/svg%3E")}
.bi-cpu{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2'%3E%3Crect x='6' y='6' width='12' height='12' rx='2'/%3E%3Crect x='9' y='9' width='6' height='6'/%3E%3Cpath d='M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4'/%3E%3C/svg%3E")}
.bi-tv{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='6' width='18' height='13' rx='2'/%3E%3Cpath d='m8 2 4 4 4-4M8 22h8'/%3E%3C/svg%3E")}
.bi-shield-lock{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5z'/%3E%3Crect x='9' y='11' width='6' height='5' rx='1'/%3E%3Cpath d='M10.5 11V9.5a1.5 1.5 0 0 1 3 0V11'/%3E%3C/svg%3E")}
.bi-gear{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3Cpath d='M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1z'/%3E%3C/svg%3E")}
.bi-arrow-right{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M5 12h14M13 6l6 6-6 6'/%3E%3C/svg%3E")}
.bi-speedometer2{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Cpath d='M4 17a9 9 0 1 1 16 0M12 13l4-4'/%3E%3Ccircle cx='12' cy='13' r='1' fill='black'/%3E%3Cpath d='M6 17h12'/%3E%3C/svg%3E")}
.bi-download{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3v12M7 10l5 5 5-5M4 21h16'/%3E%3C/svg%3E")}
.bi-list-ul{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Cpath d='M9 6h11M9 12h11M9 18h11'/%3E%3Ccircle cx='4' cy='6' r='1' fill='black'/%3E%3Ccircle cx='4' cy='12' r='1' fill='black'/%3E%3Ccircle cx='4' cy='18' r='1' fill='black'/%3E%3C/svg%3E")}
.bi-filetype-json{--bi-icon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round'%3E%3Cpath d='M9 3H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h2M15 3h2a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-2'/%3E%3C/svg%3E")}
@media(min-width:576px){.col-sm-4{width:33.333%}}@media(min-width:768px){.col-md-3{width:25%}.col-md-6{width:50%}}@media(min-width:992px){.col-lg-3{width:25%}.col-lg-4{width:33.333%}.col-lg-8{width:66.667%}}
"#;

#[cfg(test)]
mod tests {
    use super::BASE_CSS;

    #[test]
    fn every_management_icon_has_an_embedded_mask() {
        let icon_classes = [
            "broadcast",
            "file-earmark-code",
            "arrow-clockwise",
            "search",
            "list-stars",
            "info-circle",
            "cpu",
            "tv",
            "shield-lock",
            "gear",
            "arrow-right",
            "speedometer2",
            "download",
            "list-ul",
            "filetype-json",
        ];

        assert!(!BASE_CSS.contains(".bi::before"));
        for icon_class in icon_classes {
            assert!(
                BASE_CSS.contains(&format!(".bi-{icon_class}{{--bi-icon:")),
                "missing embedded icon for bi-{icon_class}"
            );
        }
    }
}
