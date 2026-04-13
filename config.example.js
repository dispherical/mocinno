module.exports = {
  servers: [
    {
      name: "nest-prov-1",
      node: "nest-prov-1",
      location: "Helsinki, Uusimaa",
      cidr: "10.60.0.2/16",
      gateway: "10.60.0.1",
      rootfs: "local-zfs:8",
      templates: [
        {
          name: "Debian 13",
          template: "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst",
        },
        {
          name: "Alpine 3.23",
          template: "alpine-3.23-default_20260116_amd64.tar.xz",
        },
        {
          name: "Fedora 43",
          template: "fedora-43-default_20260115_amd64.tar.xz",
        },
      ],
    },
  ],
};
