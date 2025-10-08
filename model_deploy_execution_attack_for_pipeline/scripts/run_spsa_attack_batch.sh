#!/bin/bash
#
# 这是一个自动化测试脚本，用于对 resources/filtered_images 目录下的所有图片运行 SPSA 对抗性攻击。
#
# 使用方法:
# ./scripts/run_spsa_attack_batch.sh <path_to_executable>
#
# 示例:
# ./scripts/run_spsa_attack_batch.sh resources/execution_files/emotion_ferplus_mnn
#
# ==============================================================================

# --- 脚本核心逻辑 ---

# 1. 设置与校验参数
# ------------------------------------------------------------------------------
BASE_DIR=$(realpath "$(dirname "$0")/..")

if [ -z "$1" ]; then
    echo "错误: 请提供目标可执行文件的路径。"
    echo "用法: $0 <path_to_executable>"
    exit 1
fi

EXECUTABLE=$1
IMAGE_DIR="$BASE_DIR/resources/filtered_images"
EXECUTABLE_NAME=$(basename "$EXECUTABLE")

echo "自动化 SPSA 批量攻击测试启动..."
echo "========================================"
echo "项目根目录: $BASE_DIR"
echo "目标程序: $EXECUTABLE"
echo "攻击图片目录: $IMAGE_DIR"
echo "----------------------------------------"

# 2. 动态推断文件路径
# ------------------------------------------------------------------------------
MODEL_DIR="$BASE_DIR/resources/models"
HOOK_CONFIG_DIR="$BASE_DIR/hook_config"
BASE_OUTPUT_DIR="$BASE_DIR/attack_results" # 所有攻击结果的根目录

HOOK_CONFIG="$HOOK_CONFIG_DIR/${EXECUTABLE_NAME}_hook_config.json"

# 解析可执行文件名以推断模型和引擎
model_base=""
engine=""
if [[ $EXECUTABLE_NAME == *"_tflite"* ]]; then
    engine="tflite"
    model_base=${EXECUTABLE_NAME%_tflite}
elif [[ $EXECUTABLE_NAME == *"_onnxruntime"* ]]; then
    engine="onnxruntime"
    model_base=${EXECUTABLE_NAME%_onnxruntime}
elif [[ $EXECUTABLE_NAME == *"_ncnn"* ]]; then
    engine="ncnn"
    model_base=${EXECUTABLE_NAME%_ncnn}
elif [[ $EXECUTABLE_NAME == *"_mnn"* ]]; then
    engine="mnn"
    model_base=${EXECUTABLE_NAME%_mnn}
else
    echo "错误: 无法从文件名 '$EXECUTABLE_NAME' 中识别推理引擎。"
    echo "文件名必须以 _tflite, _onnxruntime, _ncnn, 或 _mnn 结尾。"
    exit 1
fi

# 特殊处理需要多个模型文件的模型
if [[ "$model_base" == "fsanet_headpose" ]]; then
    echo "检测到 'fsanet_headpose' 模型，将使用多个模型文件。"
    det_model_suffix=$(echo $engine | sed 's/onnxruntime/onnx/') # onnxruntime -> onnx
    MODEL_PATHS="$MODEL_DIR/fsanet_headpose.${det_model_suffix},$MODEL_DIR/fsanet_headpose_det.${det_model_suffix}"
else
    # 对于单个模型文件的情况
    model_asset_name=""
    case $model_base in
        "age_googlenet") model_asset_name="age_googlenet" ;;
        "liveness_Vit") model_asset_name="liveness_Vit" ;;
        "emotion_ferplus") model_asset_name="emotion_ferplus" ;;
        "gender_googlenet") model_asset_name="gender_googlenet" ;;
        "pfld_landmarks") model_asset_name="pfld_landmarks" ;;
        "ssrnet_age") model_asset_name="ssrnet_age" ;;
        "ultraface_detector") model_asset_name="ultraface_detector" ;;
        "yolov5_detector") model_asset_name="yolov5_detector" ;;
        "mnist") model_asset_name="mnist" ;;
        *)
            echo "警告: 未找到模型 '$model_base' 的映射。将假定模型文件名与基础名相同。"
            model_asset_name=$model_base
            ;;
    esac

    case $engine in
        "tflite") MODEL_PATH="$MODEL_DIR/${model_asset_name}.tflite" ;;
        "onnxruntime") MODEL_PATH="$MODEL_DIR/${model_asset_name}.onnx" ;;
        "mnn") MODEL_PATH="$MODEL_DIR/${model_asset_name}.mnn" ;;
        "ncnn") 
            echo "错误: NCNN 模型 (.param/.bin) 需要两个文件，当前自动化脚本不支持。"
            exit 1
            ;;
    esac
    MODEL_PATHS=$MODEL_PATH
fi

echo "推断出的Hook配置: $HOOK_CONFIG"
echo "推断出的模型文件: $MODEL_PATHS"

# 3. 运行前检查
# ------------------------------------------------------------------------------
if [ ! -d "$IMAGE_DIR" ]; then
    echo "错误: 图片目录不存在: $IMAGE_DIR"
    exit 1
fi

for file in "$EXECUTABLE" "$HOOK_CONFIG"; do
    if [ ! -f "$file" ]; then
        echo "错误: 需要的文件不存在: $file"
        exit 1
    fi
done

IFS=',' read -ra models_to_check <<< "$MODEL_PATHS"
for model in "${models_to_check[@]}"; do
    if [ ! -f "$model" ]; then
        echo "错误: 需要的模型文件不存在: $model"
        exit 1
    fi
done

# 4. 设置环境变量
# ------------------------------------------------------------------------------
export LD_LIBRARY_PATH=$BASE_DIR/third_party/mnn/lib:$BASE_DIR/third_party/ncnn/lib:$BASE_DIR/third_party/onnxruntime/lib:$LD_LIBRARY_PATH
echo "LD_LIBRARY_PATH 已设置。"
echo "========================================"

# 5. 定义并执行攻击
# ------------------------------------------------------------------------------
ATTACK_TYPE="spsa"

# 公共攻击参数
ITERATIONS=150
L_INF_NORM=20.0
LEARNING_RATE=5

# SPSA 特定攻击参数
specific_args="--spsa-grad-samples 32 --spsa-c 0.1"

# 统计图片总数并初始化计数器
total_images=$(find "$IMAGE_DIR" -maxdepth 1 -type f | wc -l)
image_count=0

# 遍历图片目录并执行攻击
for TARGET_IMAGE in "$IMAGE_DIR"/*; do
    if [ ! -f "$TARGET_IMAGE" ]; then
        echo "跳过非文件项目: $TARGET_IMAGE"
        continue
    fi

    ((image_count++))
    IMAGE_NAME=$(basename "$TARGET_IMAGE")
    IMAGE_NAME_NO_EXT="${IMAGE_NAME%.*}"

    ATTACK_OUTPUT_DIR="$BASE_OUTPUT_DIR/${EXECUTABLE_NAME}_${ATTACK_TYPE}_${IMAGE_NAME_NO_EXT}_$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$ATTACK_OUTPUT_DIR"
    
    echo ""
    echo "--- [第 ${image_count}/${total_images} 张] 开始对 [$IMAGE_NAME] 执行 [${ATTACK_TYPE^^}] 攻击 ---"
    echo "结果将保存在: $ATTACK_OUTPUT_DIR"
    
    # 执行命令
    python3 "$BASE_DIR/src/main_attack.py" \
        --attack-type "$ATTACK_TYPE" \
        --executable "$EXECUTABLE" \
        --image "$TARGET_IMAGE" \
        --hooks "$HOOK_CONFIG" \
        --models "$MODEL_PATHS" \
        --output-dir "$ATTACK_OUTPUT_DIR" \
        --iterations "$ITERATIONS" \
        --l-inf-norm "$L_INF_NORM" \
        --learning-rate "$LEARNING_RATE" \
        --enable-stagnation-decay \
        $specific_args

    echo "--- 对 [$IMAGE_NAME] 的 [${ATTACK_TYPE^^}] 攻击完成 ---"
    echo "========================================"
done

echo "所有图片的 SPSA 攻击测试已完成！"
