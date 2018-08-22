<?php

/*
 * This file is part of the Dektrium project.
 *
 * (c) Dektrium project <http://github.com/dektrium>
 *
 * For the full copyright and license information, please view the LICENSE.md
 * file that was distributed with this source code.
 */

namespace bpopescu\rbac\controllers;

use bpopescu\rbac\Role;
use yii\web\NotFoundHttpException;
use bpopescu\rbac\Item;

/**
 * @author Dmitry Erofeev <dmeroff@gmail.com>
 */
class RoleController extends ItemControllerAbstract
{
    /** @var string */
    protected $modelClass = 'bpopescu\rbac\models\Role';
    
    protected $type = Item::TYPE_ROLE;

    /** @inheritdoc */
    protected function getItem($id)
    {
        $role = \Yii::$app->authManager->getRole($id);

        if ($role instanceof Role) {
            return $role;
        }

        throw new NotFoundHttpException;
    }
}