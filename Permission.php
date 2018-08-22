<?php
namespace bpopescu\rbac;

class Permission extends Item
{
    /**
     * @var int
     */
    public $id;

    public $type = self::TYPE_PERMISSION;
}