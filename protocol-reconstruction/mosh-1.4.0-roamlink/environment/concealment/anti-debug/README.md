# Staging slot

The generation pipeline copies `script/concealment/anti-debug/`
assets here so the Docker build can apply binary concealment
without reaching outside the task tree (same convention as the
sibling skills' environment/evasion and environment/protection
staging).
