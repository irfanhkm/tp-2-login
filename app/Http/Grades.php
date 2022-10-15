<?php
namespace App\Http;

use Illuminate\Database\Eloquent\Model;

class Grades extends Model
{
    protected $fillable = [
        'nim',
        'quiz_score',
        'quiz_score_grade',
        'task_score',
        'task_score_grade',
        'absent_score',
        'absent_score_grade',
        'practice_score',
        'practice_score_grade',
        'uas_score',
        'uas_score_grade',
    ];

    public static function boot()
    {
        parent::boot();

        self::creating(function ($model) {
            $model->quiz_score_grade = self::calculateGrade($model->quiz_score);
            $model->task_score_grade = self::calculateGrade($model->task_score);
            $model->absent_score_grade = self::calculateGrade($model->absent_score);
            $model->practice_score_grade = self::calculateGrade($model->practice_score);
            $model->uas_score_grade = self::calculateGrade($model->uas_score);
        });
    }

    private static function calculateGrade($value): string {
        if ($value <= 65) {
            return "D";
        } else if ($value <= 75) {
            return "C";
        } else if ($value <= 85) {
            return "B";
        } else if ($value <= 100) {
            return "A";
        }
        return "";
    }
}
